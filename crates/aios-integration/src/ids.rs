use serde::{Deserialize, Serialize};

macro_rules! id_newtype {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(pub String);
    };
}

id_newtype!(
    IntegrationId,
    "Unique identifier for an integration resource."
);

id_newtype!(
    VendorContractId,
    "Unique identifier for a vendor integration contract."
);

id_newtype!(
    StandardSubscriptionId,
    "Unique identifier for a standards subscription."
);

id_newtype!(ComposedSystemId, "Unique identifier for a composed system.");

id_newtype!(
    ExternalRepoBridgeId,
    "Unique identifier for an external repository bridge."
);
