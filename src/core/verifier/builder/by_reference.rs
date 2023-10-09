use url::Url;

#[derive(Debug, Clone, Default)]
pub enum ByReference {
    #[default]
    False,
    True {
        at: Url,
    },
}
