use std::error::Error;

use tonic::transport::Channel;

use crate::proto::media_service_client::MediaServiceClient;
use crate::proto::sms_service_client::SmsServiceClient;

// creates a media service grpc client
pub async fn get_media_client() -> Result<MediaServiceClient<Channel>, Box<dyn Error>> {
    let uri = std::env::var("MEDIA_SERVICE_URI").expect("MEDIA_SERVICE_URI must be set");
    let client = match MediaServiceClient::connect(uri).await {
        Ok(client) => client,
        Err(e) => {
            log::error!("Failed to connect to media service: {}", e);
            return Err(Box::new(e));
        }
    };
    Ok(client)
}

// creates a sms service grpc client
pub async fn get_sms_client() -> Result<SmsServiceClient<Channel>, Box<dyn Error>> {
    let uri = std::env::var("SMS_SERVICE_URI").expect("SMS_SERVICE_URI must be set");
    let client = match SmsServiceClient::connect(uri).await {
        Ok(client) => client,
        Err(e) => {
            log::error!("Failed to connect to sms service: {}", e);
            return Err(Box::new(e));
        }
    };
    Ok(client)
}