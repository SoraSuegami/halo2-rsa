use std::marker::PhantomData;

use crate::{AssignedInteger, AssignedLimb, UnassignedInteger};
use halo2wrong::halo2::{arithmetic::FieldExt, circuit::Value};
use maingate::{MainGate, MainGateConfig, RangeChip, RangeConfig, RegionCtx};
