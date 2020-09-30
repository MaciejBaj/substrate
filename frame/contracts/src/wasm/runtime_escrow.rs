// Copyright 2018-2020 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate. If not, see <http://www.gnu.org/licenses/>.
use crate::exec::TransferCause;
use crate::exec::*;
use crate::wasm::{PrefabWasmModule, WasmExecutable, WasmLoader};
use crate::{
    gas::{Gas, GasMeter, Token},
    rent, storage, BalanceOf, CodeHash, ContractAddressFor, ContractInfo, ContractInfoOf, Error,
    Event, RawEvent, Schedule, Trait, TrieId, TrieIdGenerator,
};
use bitflags::bitflags;
use codec::{Decode, Encode};
use frame_support::sp_runtime::DispatchResult;
use frame_support::{
    dispatch::DispatchError,
    ensure,
    storage::child,
    storage::child::{get_raw, put_raw, ChildInfo},
    traits::{Currency, ExistenceRequirement, Randomness, Time},
    weights::Weight,
    StorageMap,
};
use gateway_escrow_engine::{
    transfers::{escrow_transfer, just_transfer, BalanceOf as EscrowBalanceOf, TransferEntry},
    EscrowTrait,
};
use sp_runtime::traits::{Bounded, Convert, Hash, Saturating, Zero};
use sp_std::{cell::RefCell, convert::TryInto, marker::PhantomData, prelude::*, rc::Rc};

use sp_sandbox;
use sp_sandbox::Value;
use crate::wasm::runtime;
use crate::wasm::runtime::{ReturnCode, ReturnData, Runtime, TrapReason};

pub type MomentOf<T> = <<T as EscrowTrait>::Time as Time>::Moment;

#[derive(Debug, PartialEq, Eq, Encode, Decode, Clone)]
#[codec(compact)]
pub struct DeferredStorageWrite {
    pub dest: Vec<u8>,
    pub trie_id: Vec<u8>,
    pub key: [u8; 32],
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq, Encode, Decode, Default, Clone)]
#[codec(compact)]
pub struct CallStamp {
    pub pre_storage: Vec<u8>,
    pub post_storage: Vec<u8>,
    pub dest: Vec<u8>,
}

pub struct Config<T: EscrowTrait> {
    pub schedule: Schedule,
    pub existential_deposit: EscrowBalanceOf<T>,
    pub tombstone_deposit: EscrowBalanceOf<T>,
    pub max_depth: u32,
    pub max_value_size: u32,
}

impl<T: EscrowTrait> Config<T> {
    pub fn preload() -> Config<T> {
        Config {
            schedule: Default::default(),
            existential_deposit: T::Currency::minimum_balance(),
            tombstone_deposit: T::Currency::minimum_balance(),
            max_depth: 1,
            max_value_size: 4_294_967_295u32,
        }
    }

    /// Subsistence threshold is the extension of the minimum balance (aka existential deposit) by the
    /// tombstone deposit, required for leaving a tombstone.
    ///
    /// Rent or any contract initiated balance transfer mechanism cannot make the balance lower
    /// than the subsistence threshold in order to guarantee that a tombstone is created.
    ///
    /// The only way to completely kill a contract without a tombstone is calling `seal_terminate`.
    pub fn subsistence_threshold(&self) -> EscrowBalanceOf<T> {
        self.existential_deposit
            .saturating_add(self.tombstone_deposit)
    }

    /// The same as `subsistence_threshold` but without the need for a preloaded instance.
    ///
    /// This is for cases where this value is needed in rent calculation rather than
    /// during contract execution.
    pub fn subsistence_threshold_uncached(&self) -> EscrowBalanceOf<T> {
        T::Currency::minimum_balance().saturating_add(self.tombstone_deposit)
    }
}

pub struct RawEscrowExecState<'a> {
    pub input_data: Option<Vec<u8>>,
    pub gas_used: Gas,
    pub gas_limit: Gas,
    pub requester_available_balance: u64,
    pub requester_encoded: Vec<u8>,
    pub escrow_account_encoded: Vec<u8>,
    pub escrow_account_trie_id: ChildInfo,
    pub memory: sp_sandbox::Memory,
    pub max_value_size: u32,
    pub trap_reason: Option<TrapReason>,
    pub transfers: &'a mut Vec<TransferEntry>,
    // pub ext_escrow_transfer: Fn(Vec<u8>, Vec<u8>, D, D, &mut Vec<TransferEntry>) -> Result<(), DispatchError>
}

pub fn get_child_storage_for_current_execution<T: EscrowTrait>(
    escrow_account: &T::AccountId,
    code: T::Hash,
) -> ChildInfo {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"gateway_escrow");
    buf.extend_from_slice(&escrow_account.encode()[..]);
    buf.extend_from_slice(&code.encode()[..]);
    child::ChildInfo::new_default(T::Hashing::hash(&buf[..]).as_ref())
}

pub fn gas(
    ctx: &mut RawEscrowExecState,
    args: &[Value],
) -> Result<sp_sandbox::ReturnValue, sp_sandbox::HostError> {
    let mut args = args.iter();
    unmarshall_then_body_then_marshall!(
        args,
        ctx,
        (amount: u32) => {
            Ok(())
        }
    );
}

pub fn seal_deposit_event(
    ctx: &mut RawEscrowExecState,
    args: &[Value],
) -> Result<sp_sandbox::ReturnValue, sp_sandbox::HostError> {
    let mut args = args.iter();
    unmarshall_then_body_then_marshall!(
        args,
        ctx,
        (topics_ptr: u32, topics_len: u32, data_ptr: u32, data_len: u32) => {
            Ok(())
        }
    );
}

pub fn seal_input(
    ctx: &mut RawEscrowExecState,
    args: &[Value],
) -> Result<sp_sandbox::ReturnValue, sp_sandbox::HostError> {
    let mut args = args.iter();
    unmarshall_then_body_then_marshall!(
        args,
        ctx,
        (buf_ptr: u32, buf_len_ptr: u32) => {
            if let Some(input) = ctx.input_data.take() {
                write_sandbox_output(ctx, buf_ptr, buf_len_ptr, &input, false)
            } else {
                Err(sp_sandbox::HostError)
            }
        }
    );
}

pub fn ext_escrow_transfer<T: EscrowTrait>(
    escrow_account_encoded: Vec<u8>,
    requester_encoded: Vec<u8>,
    target_to_decoded: <T as frame_system::Trait>::AccountId,
    value_decoded: EscrowBalanceOf<T>,
    mut transfers: &mut Vec<TransferEntry>,
) -> Result<(), DispatchError> {
    escrow_transfer::<T>(
        &T::AccountId::decode(&mut &escrow_account_encoded[..]).unwrap(),
        &T::AccountId::decode(&mut &requester_encoded[..]).unwrap(),
        &target_to_decoded,
        value_decoded,
        transfers,
    )
}

pub fn seal_transfer(
    ctx: &mut RawEscrowExecState,
    args: &[Value],
) -> Result<sp_sandbox::ReturnValue, sp_sandbox::HostError> {
    let mut args = args.iter();
    unmarshall_then_body_then_marshall!(
        args,
        ctx,
        (account_ptr: u32, account_len: u32, value_ptr: u32, value_len: u32) -> ReturnCode => {
            let callee_raw: u64 = read_sandbox_memory_as(ctx, account_ptr, account_len)?;
            let val_num: u32 = read_sandbox_memory_as(ctx, value_ptr, value_len)?;
            // Not to complicate the context here, there is no dependency on a trait here.
            // Check whether the
            if val_num >= ctx.requester_available_balance as u32 {
                return Ok(ReturnCode::BelowSubsistenceThreshold);
            }
            ctx.requester_available_balance -= (val_num as u64);

            ctx.transfers.push(TransferEntry {
                to: callee_raw.encode(),
                value: val_num,
                data: vec![],
            });

            Ok(ReturnCode::Success)
        }
    );
}

pub fn seal_return(
    ctx: &mut RawEscrowExecState,
    args: &[Value],
) -> Result<sp_sandbox::ReturnValue, sp_sandbox::HostError> {
    let mut args = args.iter();
    unmarshall_then_body_then_marshall!(
        args,
        ctx,
        (flags: u32, data_ptr: u32, data_len: u32) => {
            ctx.trap_reason = Some(TrapReason::Return(ReturnData {
                flags,
                data: read_sandbox_memory(ctx, data_ptr, data_len)?,
            }));

            // The trap mechanism is used to immediately terminate the execution.
            // This trap should be handled appropriately before returning the result
            // to the user of this crate.
            Err(sp_sandbox::HostError)
        }
    );
}

pub fn seal_get_storage(
    ctx: &mut RawEscrowExecState,
    args: &[Value],
) -> Result<sp_sandbox::ReturnValue, sp_sandbox::HostError> {
    let mut args = args.iter();
    unmarshall_then_body_then_marshall!(
        args,
        ctx,
        (key_ptr: u32, out_ptr: u32, out_len_ptr: u32) -> ReturnCode => {
            let mut key: StorageKey = [0; 32];
            read_sandbox_memory_into_buf(ctx, key_ptr, &mut key)?;
            if let Some(value) = get_raw(&ctx.escrow_account_trie_id, &key) {
                write_sandbox_output(ctx, out_ptr, out_len_ptr, &value, false)?;
                Ok(ReturnCode::Success)
            } else {
                Ok(ReturnCode::KeyNotFound)
            }
            // Ok(0 as u32)
        }
    );
}

pub fn seal_set_storage(
    ctx: &mut RawEscrowExecState,
    args: &[Value],
) -> Result<sp_sandbox::ReturnValue, sp_sandbox::HostError> {
    let mut args = args.iter();
    unmarshall_then_body_then_marshall!(
        args,
        ctx,
        (key_ptr: u32, value_ptr: u32, value_len: u32) => {
            if value_len > ctx.max_value_size {
                // Bail out if value length exceeds the set maximum value size.
                return Err(sp_sandbox::HostError);
            }
            let mut key: StorageKey = [0; 32];
            read_sandbox_memory_into_buf(ctx, key_ptr, &mut key)?;
            let value = Some(read_sandbox_memory(ctx, value_ptr, value_len)?);

            match value {
                Some(new_value) => child::put_raw(&ctx.escrow_account_trie_id, &key, &new_value[..]),
                None => child::kill(&ctx.escrow_account_trie_id, &key),
            }
            Ok(())
        }
    );
}

pub fn to_execution_result(
    exec_state: RawEscrowExecState,
    sandbox_result: Result<sp_sandbox::ReturnValue, sp_sandbox::Error>,
) -> ExecResult {
    // If a trap reason is set we base our decision solely on that.
    if let Some(trap_reason) = exec_state.trap_reason {
        return match trap_reason {
            // The trap was the result of the execution `return` host function.
            TrapReason::Return(ReturnData { flags, data }) => {
                let flags = ReturnFlags::from_bits(flags)
                    .ok_or_else(|| "used reserved bit in return flags")?;
                Ok(ExecReturnValue { flags, data })
            }
            TrapReason::Termination => Ok(ExecReturnValue {
                flags: ReturnFlags::empty(),
                data: Vec::new(),
            }),
            TrapReason::Restoration => Ok(ExecReturnValue {
                flags: ReturnFlags::empty(),
                data: Vec::new(),
            }),
            TrapReason::SupervisorError(error) => Err(error)?,
        };
    }

    // Check the exact type of the error.
    match sandbox_result {
        // No traps were generated. Proceed normally.
        Ok(_) => Ok(ExecReturnValue {
            flags: ReturnFlags::empty(),
            data: Vec::new(),
        }),
        // `Error::Module` is returned only if instantiation or linking failed (i.e.
        // wasm binary tried to import a function that is not provided by the host).
        // This shouldn't happen because validation process ought to reject such binaries.
        //
        // Because panics are really undesirable in the runtime code, we treat this as
        // a trap for now. Eventually, we might want to revisit this.
        Err(sp_sandbox::Error::Module) => Err("validation error")?,
        // Any other kind of a trap should result in a failure.
        Err(sp_sandbox::Error::Execution) | Err(sp_sandbox::Error::OutOfBounds) => {
            Err(ExecError {
                /// The reason why the execution failed.
                error: DispatchError::Other("Contract Trapped"),
                // Origin of the error.
                origin: ErrorOrigin::Callee,
            })?
        }
    }
}

pub fn raw_escrow_call<T: EscrowTrait>(
    escrow_account: &T::AccountId,
    requester: &T::AccountId,
    transfer_dest: &T::AccountId,
    value: EscrowBalanceOf<T>,
    gas_limit: Gas,
    input_data: Vec<u8>,
    mut transfers: &mut Vec<TransferEntry>,
    mut deferred_storage_writes: &mut Vec<DeferredStorageWrite>,
    mut call_stamps: &mut Vec<CallStamp>,
    exec: &WasmExecutable,
    code_hash: T::Hash,
) -> ExecResult {
    if value > EscrowBalanceOf::<T>::zero() {
        escrow_transfer::<T>(
            &escrow_account.clone(),
            &requester.clone(),
            &transfer_dest.clone(),
            EscrowBalanceOf::<T>::from(TryInto::<u32>::try_into(value).ok().unwrap()),
            transfers,
        );
    }
    let escrow_account_trie_id =
        get_child_storage_for_current_execution::<T>(escrow_account, code_hash);

    let pre_storage = child::root(&escrow_account_trie_id.clone());

    let memory =
        sp_sandbox::Memory::new(exec.prefab_module.initial, Some(exec.prefab_module.maximum))
            .unwrap_or_else(|_| {
                // unlike `.expect`, explicit panic preserves the source location.
                // Needed as we can't use `RUST_BACKTRACE` in here.
                panic!(
                    "exec.prefab_module.initial can't be greater than exec.prefab_module.maximum;
						thus Memory::new must not fail;
						qed"
                )
            });

    let mut env_builder = sp_sandbox::EnvironmentDefinitionBuilder::new();
    env_builder.add_memory(
        crate::wasm::prepare::IMPORT_MODULE_MEMORY,
        "memory",
        memory.clone(),
    );

    let mut inner_exec_transfers = Vec::<TransferEntry>::new();

    let mut state = RawEscrowExecState {
        gas_used: 0,
        gas_limit,
        requester_available_balance: TryInto::<u64>::try_into(T::Currency::free_balance(
            &requester,
        ))
        .ok()
        .unwrap(),
        requester_encoded: requester.encode(),
        escrow_account_encoded: escrow_account.encode(),
        escrow_account_trie_id: escrow_account_trie_id.clone(),
        memory,
        input_data: Some(input_data),
        max_value_size: u32::MAX,
        trap_reason: None,
        transfers: &mut inner_exec_transfers,
    };

    env_builder.add_host_func(crate::wasm::prepare::IMPORT_MODULE_FN, "gas", gas);
    env_builder.add_host_func(
        crate::wasm::prepare::IMPORT_MODULE_FN,
        "seal_input",
        seal_input,
    );
    env_builder.add_host_func(
        crate::wasm::prepare::IMPORT_MODULE_FN,
        "seal_return",
        seal_return,
    );
    env_builder.add_host_func(
        crate::wasm::prepare::IMPORT_MODULE_FN,
        "seal_deposit_event",
        seal_deposit_event,
    );
    env_builder.add_host_func(
        crate::wasm::prepare::IMPORT_MODULE_FN,
        "seal_set_storage",
        seal_set_storage,
    );
    env_builder.add_host_func(
        crate::wasm::prepare::IMPORT_MODULE_FN,
        "seal_get_storage",
        seal_get_storage,
    );
    // Seal transfer don't really transfer many but add an extra entry into the deferred transfers, which are released at the end of this call to the escrow account.
    env_builder.add_host_func(
        crate::wasm::prepare::IMPORT_MODULE_FN,
        "seal_transfer",
        seal_transfer,
    );

    let mut instance =
        match sp_sandbox::Instance::new(&exec.prefab_module.code, &env_builder, &mut state) {
            Ok(instance) => instance,
            Err(_err) => Err(ExecError {
                error: DispatchError::Other(
                    "Failed instantiating code with sandbox instance for provided WASM code.",
                ),
                origin: ErrorOrigin::Caller,
            })?,
        };

    let result = instance.invoke(exec.entrypoint_name, &[], &mut state);

    call_stamps.push(CallStamp {
        pre_storage,
        post_storage: child::root(&escrow_account_trie_id.clone()),
        dest: T::AccountId::encode(&escrow_account.clone()),
    });

    match result {
        Ok(_) => {
            // Ensuring successful execution escrow transfers from within the contract.
            for transfer in state.transfers.iter() {
                escrow_transfer::<T>(
                    &escrow_account.clone(),
                    &requester.clone(),
                    &T::AccountId::decode(&mut &transfer.to[..]).unwrap(),
                    EscrowBalanceOf::<T>::from(
                        TryInto::<u32>::try_into(transfer.value).ok().unwrap(),
                    ),
                    transfers,
                );
            }
        }
        _ => (),
    }
    to_execution_result(state, result)
}

fn read_sandbox_memory(
    ctx: &mut RawEscrowExecState,
    ptr: u32,
    len: u32,
) -> Result<Vec<u8>, sp_sandbox::HostError> {
    let mut buf = vec![0u8; len as usize];
    ctx.memory
        .get(ptr, buf.as_mut_slice())
        .map_err(|_| sp_sandbox::HostError)?;
    Ok(buf)
}

pub fn read_sandbox_memory_as<D: Decode>(
    ctx: &mut RawEscrowExecState,
    ptr: u32,
    len: u32,
) -> Result<D, sp_sandbox::HostError> {
    let buf = read_sandbox_memory(ctx, ptr, len)?;
    D::decode(&mut &buf[..]).map_err(|_| sp_sandbox::HostError)
}

fn read_sandbox_memory_into_buf(
    ctx: &mut RawEscrowExecState,
    ptr: u32,
    buf: &mut [u8],
) -> Result<(), sp_sandbox::HostError> {
    ctx.memory.get(ptr, buf).map_err(|_| sp_sandbox::HostError)
}

fn write_sandbox_output(
    ctx: &mut RawEscrowExecState,
    out_ptr: u32,
    out_len_ptr: u32,
    buf: &[u8],
    allow_skip: bool,
) -> Result<(), sp_sandbox::HostError> {
    if allow_skip && out_ptr == u32::max_value() {
        return Ok(());
    }

    let buf_len = buf.len() as u32;
    let len: u32 = read_sandbox_memory_as(ctx, out_len_ptr, 4)?;

    if len < buf_len {
        Err(sp_sandbox::HostError)?
    }

    ctx.memory.set(out_ptr, buf)?;
    ctx.memory.set(out_len_ptr, &buf_len.encode())?;

    Ok(())
}
