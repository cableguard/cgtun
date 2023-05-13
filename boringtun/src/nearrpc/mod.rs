
use tracing::Level;
use base64;
use reqwest::blocking::Client;

pub mod nearrpcall{
pub fn rpc_call(
    id: &str,
    account_id: &str,
    method_name: &str,
    args: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let url = "https://rpc.testnet.near.org";
    let json_data = format!(
        r#"{{
            "jsonrpc": "2.0",
            "id": "{}",
            "method": "query",
            "params": {{
                "request_type": "call_function",
                "finality": "final",
                "account_id": "{}",
                "method_name": "{}",
                "args_base64": "{}"
            }}
        }}"#,
        id, account_id, method_name, base64::encode(args);
    );

    let response = client
        .post(url)
        .body(json_data)
        .header("Content-Type", "application/json")
        .send()?;

    let response_text = response.text()?;
    println!("{}", response_text);

    Ok(())
    }
} 