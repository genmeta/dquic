use derive_builder::Builder;
use serde::{Deserialize, Serialize};

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(default, setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct Error {
    code: Option<u64>,
    message: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Builder, Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(default, setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct Warning {
    code: Option<u64>,
    message: Option<String>,
}

#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct Info {
    message: String,
}

#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct Debug {
    message: String,
}

#[derive(Builder, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[builder(setter(into, strip_option), build_fn(private, name = "fallible_build"))]
pub struct Verbose {
    message: String,
}

crate::gen_builder_method! {
    ErrorBuilder   => Error;
    WarningBuilder => Warning;
    InfoBuilder    => Info;
    DebugBuilder   => Debug;
    VerboseBuilder => Verbose;
}

mod rollback {
    use super::*;
    use crate::{build, legacy};

    impl From<Error> for legacy::GenericError {
        fn from(value: Error) -> Self {
            build!(legacy::GenericError {
                ?code: value.code,
                ?message: value.message
            })
        }
    }

    impl From<Warning> for legacy::GenericWarning {
        fn from(value: Warning) -> Self {
            build!(legacy::GenericWarning {
                ?code: value.code,
                ?message: value.message
            })
        }
    }

    impl From<Info> for legacy::GenericInfo {
        fn from(value: Info) -> Self {
            build!(legacy::GenericInfo { message: value.message })
        }
    }

    impl From<Debug> for legacy::GenericDebug {
        fn from(value: Debug) -> Self {
            build!(legacy::GenericDebug { message: value.message })
        }
    }

    impl From<Verbose> for legacy::GenericVerbose {
        fn from(value: Verbose) -> Self {
            build!(legacy::GenericVerbose { message: value.message })
        }
    }
}
