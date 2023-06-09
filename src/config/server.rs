use mongodb::bson::Document;

use crate::{config, proto};
use crate::proto::auth_service_server::AuthServiceServer;
use crate::server::AuthServiceImpl;

pub(crate) async fn init_server() -> Result<(), Box<dyn std::error::Error>> {

    // define the socket address from .env
    let port = std::env::var("PORT").expect("PORT must be set");
    // bind to address
    let host = "[::]";
    let addr = format!("{}:{}", &host, &port).parse().unwrap();

    let mongo_db = match config::db::init_database().await {
        Ok(db) => db,
        Err(e) => {
            log::error!("failed to connect to database: {}", e);
            return Err(e.into());
        }
    };

    let token_collection_name =
        std::env::var("TOKEN_COLLECTION").expect("TOKEN_COLLECTION must be set");
    let account_collection_name =
        std::env::var("ACCOUNT_COLLECTION").expect("ACCOUNT_COLLECTION must be set");
    let country_collection_name =
        std::env::var("COUNTRY_COLLECTION").expect("COUNTRY_COLLECTION must be set");
    let college_collection_name =
        std::env::var("COLLEGE_COLLECTION").expect("COLLEGE_COLLECTION must be set");

    // create collections based on proto
    let account_collection = mongo_db.collection::<Document>(&account_collection_name);
    let token_collection =
        mongo_db.collection::<Document>(&token_collection_name);
    let country_collection =
        mongo_db.collection::<Document>(&country_collection_name);
    let college_collection =
        mongo_db.collection::<Document>(&college_collection_name);

    // instantiate the services
    let auth_service = AuthServiceImpl::new(
        account_collection.clone(),
        token_collection.clone(),
        country_collection.clone(),
        college_collection.clone(),
    );

    // reflection service
    let service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::AUTH_FILE_DESCRIPTOR_SET)
        .build()
        .unwrap();

    log::info!("initiating auth grpc server on port {}", &port);

    // create a new instance of the grpc server
    tonic::transport::Server::builder()
        .add_service(service)
        .add_service(AuthServiceServer::new(auth_service))
        .serve(addr)
        .await?;

    Ok(())
}