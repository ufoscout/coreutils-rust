pub fn new() -> JsonService {
    JsonService {}
}

#[derive(Clone)]
pub struct JsonService {}

impl JsonService {
    pub fn to_json<T: Sized + serde::ser::Serialize>(
        &self,
        value: &T,
    ) -> serde_json::Result<String> {
        serde_json::to_string(value)
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn from_json<'a, T: serde::de::Deserialize<'a>>(
        &self,
        s: &'a str,
    ) -> serde_json::Result<T> {
        serde_json::from_str(s)
    }
}

#[cfg(test)]
mod test {

    use serde_derive::{Deserialize, Serialize};

    #[test]
    fn service_should_be_send_and_sync() {
        call_me_with_send_and_sync(super::new());
    }

    fn call_me_with_send_and_sync<T: Send + Sync>(_: T) {}

    #[test]
    fn should_serialize() {
        let json = super::new();

        let obj = ColorGroup {
            id: 123,
            color_name: "Red".to_string(),
        };

        let json_string = json.to_json(&obj).unwrap();
        println!("Json string: [{}]", json_string);
        assert_eq!(
            "{\"id\":123,\"colorName\":\"Red\"}".to_string(),
            json_string
        );
    }

    #[test]
    fn should_deserialize() {
        let json = super::new();

        let json_string = "{\"id\":123,\"colorName\":\"Red\"}".to_string();
        let deserialized: ColorGroup = json.from_json(&json_string).unwrap();

        assert_eq!(123, deserialized.id);
        assert_eq!("Red".to_string(), deserialized.color_name);
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ColorGroup {
        id: i64,
        color_name: String,
    }

}
