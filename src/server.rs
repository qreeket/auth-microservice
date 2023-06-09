use std::error::Error;

use chrono::{DateTime, Utc};
use futures::StreamExt;
use log::error;
use mongodb::bson;
use mongodb::bson::{Bson, doc, Document};
use mongodb::options::FindOptions;
use regex::Regex;
use tonic::{IntoRequest, Request, Response, Status};
use tonic::metadata::{MetadataMap, MetadataValue};

use crate::{client, config, utils};
use crate::config::{locale, tokenizer};
use crate::proto::{Account, auth_service_server::AuthService, AuthenticateWithSocialAccountRequest, College, Country,
                   GetCollegesResponse, GetCountriesResponse, LoginRequest, MediaType, RegisterRequest,
                   RequestPasswordResetRequest, ResetPasswordRequest, UploadMediaRequest, UserType, ValidateAccessTokenResponse};
use crate::proto::authenticate_with_social_account_request::AuthAvatar;
use crate::proto::login_request::Payload;
use crate::proto::register_request::Avatar;
use crate::proto::request_password_reset_request::RequestPasswordResetPayload;
use crate::proto::reset_password_request::ResetPayload;

rust_i18n::i18n!("locales");

#[derive(Debug)]
pub struct AuthServiceImpl {
    pub account_col: mongodb::Collection<Document>,
    pub token_col: mongodb::Collection<Document>,
    pub country_col: mongodb::Collection<Document>,
    pub college_col: mongodb::Collection<Document>,
}

impl AuthServiceImpl {
    pub fn new(
        account_col: mongodb::Collection<Document>,
        token_col: mongodb::Collection<Document>,
        country_col: mongodb::Collection<Document>,
        college_col: mongodb::Collection<Document>,
    ) -> Self {
        Self {
            account_col,
            token_col,
            country_col,
            college_col,
        }
    }
}

#[tonic::async_trait]
impl AuthService for AuthServiceImpl {
    // done
    async fn login(&self, request: Request<LoginRequest>) -> Result<Response<String>, Status> {
        // validate language id
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // verify public token
        match config::session_manager::verify_public_access_token(&request.metadata(), &language_id)
            .await
        {
            Ok(_) => (),
            Err(e) => {
                return Err(e);
            }
        };

        // parse request
        let req = request.into_inner();
        let mut key = "".to_string();
        let mut value = "".to_string();
        match &req.payload.unwrap() {
            Payload::PhoneNumber(phone_number) => {
                let phone_number = phone_number.to_string();
                if phone_number.len() != 0 {
                    key = "phone_number".to_string();
                    value = phone_number;
                }
            }
            Payload::Email(email) => {
                let email = email.to_string();
                if email.len() != 0 {
                    key = "email".to_string();
                    value = email;
                }
            }
        };

        // get account from db
        let filter = doc! {key: value};
        let account = match self
            .account_col
            .find_one(filter, None)
            .await
        {
            Ok(account) => account,
            Err(_) => {
                return Err(Status::not_found(t!("account_not_found")));
            }
        };

        // create a new session for account
        match account {
            Some(account_doc) => {
                // compare password
                let is_valid_password = match tokenizer::compare_password(
                    &req.password,
                    &account_doc.get_str("password").unwrap().to_string(),
                ) {
                    Ok(is_valid) => is_valid,
                    Err(_) => {
                        return Err(Status::unauthenticated(t!("invalid_credentials")));
                    }
                };
                if !is_valid_password {
                    return Err(Status::unauthenticated(t!("invalid_credentials")));
                }

                // compare country id
                let is_valid_country = match account_doc.get_str("country_id") {
                    Ok(country_id) => {
                        if country_id == &req.country_id {
                            true
                        } else {
                            false
                        }
                    }
                    Err(_) => false,
                };
                if !is_valid_country {
                    return Err(Status::unauthenticated(t!("invalid_credentials")));
                }

                // generate access token
                let access_token = match config::session_manager::create_access_token(
                    &account_doc.get_str("id").unwrap().to_string(),
                    &language_id,
                    &self.token_col,
                )
                    .await {
                    Ok(access_token) => access_token,
                    Err(err) => {
                        error!("create access token error: {}", err);
                        return Err(Status::internal(t!("auth_failed")));
                    }
                };
                Ok(Response::new(access_token))
            }
            None => {
                return Err(Status::not_found(t!("account_not_found")));
            }
        }
    }

    // done
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<String>, Status> {

        // validate language id
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // verify public token
        match config::session_manager::verify_public_access_token(&request.metadata(), &language_id)
            .await
        {
            Ok(_) => (),
            Err(e) => {
                return Err(e);
            }
        };

        // parse request
        let req = request.into_inner();
        let email = &req.email.unwrap().to_string();
        let phone_number = &req.phone_number.unwrap().to_string();

        // get account from db
        let has_existing_account = match self
            .account_col
            .find_one(doc! {"email": &email}, None)
            .await
            .unwrap()
        {
            Some(_) => {
                true
            }
            None => false,
        };
        if has_existing_account {
            return Err(Status::already_exists(t!("account_exists")));
        }

        // encrypt password
        let hashed_password = match tokenizer::hash_password(&req.password) {
            Ok(hashed_password) => hashed_password,
            Err(_) => {
                return Err(Status::internal(t!("password_encryption_failed")));
            }
        };

        // upload profile picture
        let avatar = match req.avatar {
            Some(avatar_url) => {
                match avatar_url {
                    Avatar::AvatarData(avatar) => match _upload_media(&avatar, &phone_number, "avatar").await {
                        Ok(avatar) => avatar,
                        Err(_) => "".to_string(),
                    },
                    Avatar::AvatarUrl(url) => url,
                }
            }
            None => "".to_string(),
        };

        // create a new account
        let mut account_doc = doc! {
            "phone_number" : &phone_number,
            "username" : &req.username,
            "language_id" : &language_id,
            "created_at": _create_timestamp_field(),
            "updated_at": _create_timestamp_field(),    // aka: last login
            "avatar_url" : avatar,
            "password" : &hashed_password,
            "country_id" : &req.country_id,
            "is_verified" : Some(false),
            "college_id" : &req.college_id,
            "email" : &email,
            "device_id" : "",
            "device_token" : "",
            "device_type" : "",
            "user_type" : UserType::Standard as i32,
        };

        // save account to db
        match self
            .account_col
            .insert_one(&account_doc.clone(), None)
            .await
        {
            Ok(result) => {
                // update id field with result
                account_doc.insert("id", &result.inserted_id.as_object_id().unwrap().to_hex());

                // replace one in db with updated account doc
                match self
                    .account_col
                    .replace_one(doc! {"email": &email}, &account_doc, None)
                    .await
                {
                    Ok(_) => (),
                    Err(_) => {
                        return Err(Status::internal(t!("auth_failed")));
                    }
                }

                // create a new access token
                let access_token = config::session_manager::create_access_token(
                    &account_doc.get_str("id").unwrap().to_string(),
                    &language_id,
                    &self.token_col,
                )
                    .await
                    .unwrap();
                Ok(Response::new(access_token))
            }
            Err(_) => {
                return Err(Status::internal(t!("auth_failed")));
            }
        }
    }

    // done
    async fn reset_password(
        &self,
        request: Request<ResetPasswordRequest>,
    ) -> Result<Response<String>, Status> {
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // verify public token
        match config::session_manager::verify_public_access_token(&request.metadata(), &language_id)
            .await
        {
            Ok(_) => (),
            Err(e) => {
                return Err(e);
            }
        };

        // get request
        let req = request.into_inner();

        // verify token from request payload
        match config::session_manager::verify_reset_password_token(
            &req.reset_token,
            &language_id,
        ).await {
            Ok(_) => (),
            Err(_) => {
                return Err(Status::permission_denied(t!("invalid_reset_token")));
            }
        };

        // get phone number / email from request
        let filter = match &req.reset_payload.unwrap() {
            ResetPayload::Email(email) => doc! {"email": email},
            ResetPayload::PhoneNumber(phone_number) => doc! {"phone_number": phone_number},
        };

        // find account by phone number
        let mut account_doc = match self
            .account_col
            .find_one(filter.to_owned(), None)
            .await
            .unwrap()
        {
            Some(acct_doc) => acct_doc,
            None => {
                return Err(Status::not_found(t!("account_not_found")));
            }
        };

        // encrypt password
        let hashed_password = match tokenizer::hash_password(&req.password) {
            Ok(hashed_password) => hashed_password,
            Err(_) => {
                return Err(Status::internal(t!("password_encryption_failed")));
            }
        };

        // update password
        account_doc.insert("password", &hashed_password);

        // replace one in db with updated account doc
        match self
            .account_col
            .replace_one(filter.to_owned(), &account_doc, None)
            .await
        {
            Ok(_) => {
                // create access token
                let access_token = config::session_manager::create_access_token(
                    &account_doc.get_str("id").unwrap().to_string(),
                    &language_id,
                    &self.token_col,
                )
                    .await
                    .unwrap();
                Ok(Response::new(access_token))
            }
            Err(_) => {
                return Err(Status::internal(t!("password_reset_failed")));
            }
        }
    }

    // done
    async fn request_password_reset(&self, request: Request<RequestPasswordResetRequest>) -> Result<Response<String>, Status> {
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // verify public token
        match config::session_manager::verify_public_access_token(&request.metadata(), &language_id)
            .await
        {
            Ok(_) => (),
            Err(e) => {
                return Err(e);
            }
        };

        // get request
        let req = request.into_inner();

        // get phone number / email from request
        let filter = match &req.request_password_reset_payload.unwrap() {
            RequestPasswordResetPayload::Email(email) => doc! {"email": email},
            RequestPasswordResetPayload::PhoneNumber(phone_number) => doc! {"phone_number": phone_number},
        };

        // find account by phone number / email
        let account_doc = match self
            .account_col
            .find_one(filter.to_owned(), None)
            .await
            .unwrap()
        {
            Some(acct_doc) => acct_doc,
            None => {
                return Err(Status::not_found(t!("account_not_found")));
            }
        };

        let mut client = match client::get_sms_client().await {
            Ok(client) => client,
            Err(_) => {
                return Err(Status::internal(t!("sms_send_failed")));
            }
        };

        // send phone verification code request
        let mut req_payload = IntoRequest::<String>::into_request(account_doc.get_str("phone_number").unwrap().to_string());
        req_payload.metadata_mut().insert(
            "x-language-id",
            MetadataValue::from_str(&language_id).unwrap(),
        );

        match client.send_phone_verification_code(req_payload).await {
            Ok(_) => {
                // create reset token
                let reset_token = config::session_manager::create_reset_token(&language_id).await.unwrap();
                Ok(Response::new(reset_token))
            }
            Err(_) => {
                // sms_send_not_supported
                Err(Status::internal(t!("sms_send_failed")))
            }
        }
    }

    // done
    async fn logout(&self, request: Request<()>) -> Result<Response<()>, Status> {
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // verify public token
        match config::session_manager::verify_access_token(
            &request.metadata(),
            &language_id,
            &self.token_col,
        )
            .await
        {
            Ok(_) => (),
            Err(e) => {
                return Err(e);
            }
        };

        match config::session_manager::clear_access_token(&request.metadata(), &self.token_col)
            .await
        {
            Ok(()) => Ok(Response::new(())),
            Err(e) => {
                return Err(e);
            }
        }
    }

    // done
    async fn verify_password(&self, request: Request<String>) -> Result<Response<()>, Status> {
        // validate language id
        match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // verify access token
        let token_payload = match config::session_manager::verify_access_token(
            &request.metadata(),
            &rust_i18n::locale().as_str().to_string(),
            &self.token_col,
        )
            .await
        {
            Ok(result) => (result.0, result.1),
            Err(e) => {
                return Err(e);
            }
        };

        // get account id from token payload and language id
        let account_id = token_payload.0;

        // find account by id
        let account_doc = match self
            .account_col
            .find_one(doc! {"id": &account_id}, None)
            .await
            .unwrap()
        {
            Some(acct_doc) => acct_doc,
            None => {
                return Err(Status::not_found(t!("account_not_found")));
            }
        };

        // get password from request
        let password = request.into_inner();

        // verify password
        match tokenizer::compare_password(&password, &account_doc.get_str("password").unwrap()) {
            Ok(_) => Ok(Response::new(())),
            Err(_) => {
                return Err(Status::internal(t!("invalid_credentials")));
            }
        }
    }

    // done
    async fn upgrade_to_premium(&self, request: Request<()>) -> Result<Response<()>, Status> {
        // validate language id
        match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // verify access token
        let token_payload = match config::session_manager::verify_access_token(
            &request.metadata(),
            &rust_i18n::locale().as_str().to_string(),
            &self.token_col,
        )
            .await
        {
            Ok(result) => (result.0, result.1),
            Err(e) => {
                return Err(e);
            }
        };

        // get account id from token payload and language id
        let account_id = token_payload.0;

        // find account by id
        let account_doc = match self
            .account_col
            .find_one(doc! {"id": &account_id}, None)
            .await
            .unwrap()
        {
            Some(acct_doc) => acct_doc,
            None => {
                return Err(Status::not_found(t!("account_not_found")));
            }
        };

        // check if account is already premium
        if account_doc.get_i32("user_type").unwrap() == UserType::Premium as i32 {
            return Err(Status::already_exists(t!("account_already_premium")));
        }

        // update account to premium
        match self
            .account_col
            .update_one(
                doc! {"id": &account_id},
                doc! {"$set": {"user_type": UserType::Premium as i32}},
                None,
            )
            .await
        {
            Ok(_) => Ok(Response::new(())),
            Err(_) => {
                return Err(Status::internal(t!("upgrade_to_premium_failed")));
            }
        }
    }

    // done
    async fn downgrade_to_standard(&self, request: Request<()>) -> Result<Response<()>, Status> {
        // validate language id
        match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // verify access token
        let token_payload = match config::session_manager::verify_access_token(
            &request.metadata(),
            &rust_i18n::locale().as_str().to_string(),
            &self.token_col,
        )
            .await
        {
            Ok(result) => (result.0, result.1),
            Err(e) => {
                return Err(e);
            }
        };

        // get account id from token payload and language id
        let account_id = token_payload.0;

        // find account by id
        let account_doc = match self
            .account_col
            .find_one(doc! {"id": &account_id}, None)
            .await
            .unwrap()
        {
            Some(acct_doc) => acct_doc,
            None => {
                return Err(Status::not_found(t!("account_not_found")));
            }
        };

        // check if account is already premium
        if account_doc.get_i32("user_type").unwrap() == UserType::Standard as i32 {
            return Err(Status::already_exists(t!("account_already_standard")));
        }

        // update account to premium
        match self
            .account_col
            .update_one(
                doc! {"id": &account_id},
                doc! {"$set": {"user_type": UserType::Standard as i32}},
                None,
            )
            .await
        {
            Ok(_) => Ok(Response::new(())),
            Err(_) => {
                return Err(Status::internal(t!("downgrade_to_standard_failed")));
            }
        }
    }

    // done
    async fn request_public_access_token(
        &self,
        _: Request<()>,
    ) -> Result<Response<String>, Status> {
        // generate a new public token from tokenizer
        match tokenizer::generate_public_token(&rust_i18n::locale()) {
            // return token if successful else return status internal
            Ok(token) => Ok(Response::new(token)),
            Err(_) => {
                Err(Status::internal(t!("access_denied")))
            }
        }
    }

    // done
    async fn validate_access_token(
        &self,
        request: Request<()>,
    ) -> Result<Response<ValidateAccessTokenResponse>, Status> {
        let language_id = match _validate_language_id_from_request(&request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // get auth type from request
        let use_private_token = match _get_authentication_type_from_metadata(&request.metadata()) {
            Ok(use_private_token) => use_private_token,
            Err(e) => {
                return Err(e);
            }
        };

        if use_private_token {
            // verify access token
            let token = match config::session_manager::verify_access_token(
                &request.metadata(),
                &language_id,
                &self.token_col,
            )
                .await
            {
                Ok(token) => token,
                Err(e) => {
                    return Err(e);
                }
            };

            // get account by id
            let account_doc = match self
                .account_col
                .find_one(doc! {"id": &token.0}, None)
                .await
                .unwrap()
            {
                Some(acct_doc) => acct_doc,
                None => {
                    return Err(Status::not_found(t!("account_not_found")));
                }
            };

            Ok(Response::new(ValidateAccessTokenResponse {
                account_id: Some(account_doc.get_str("id").unwrap().to_string()),
                phone_number: Some(account_doc.get_str("phone_number").unwrap().to_string()),
                username: Some(account_doc.get_str("username").unwrap().to_string()),
            }))
        } else {
            // verify public token
            match config::session_manager::verify_public_access_token(
                &request.metadata(),
                &language_id,
            )
                .await
            {
                Ok(_) => Ok(Response::new(ValidateAccessTokenResponse {
                    account_id: None,
                    phone_number: None,
                    username: None,
                })),
                Err(e) => Err(e),
            }
        }
    }

    // done
    async fn get_account(&self, request: Request<()>) -> Result<Response<Account>, Status> {
        // validate language id
        match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // verify access token
        let token_payload = match config::session_manager::verify_access_token(
            &request.metadata(),
            &rust_i18n::locale().as_str().to_string(),
            &self.token_col,
        )
            .await
        {
            Ok(result) => (result.0, result.1),
            Err(e) => {
                return Err(e);
            }
        };

        // get account id from token payload and language id
        let account_id = token_payload.0;
        let language_id = token_payload.1;

        // find account by id
        let account_doc = match self
            .account_col
            .find_one(doc! {"id": &account_id}, None)
            .await
            .unwrap()
        {
            Some(acct_doc) => acct_doc,
            None => {
                return Err(Status::not_found(t!("account_not_found")));
            }
        };

        // create account object from account doc
        let account = Account {
            id: account_doc.get_str("id").unwrap().to_string(),
            phone_number: Some(account_doc.get_str("phone_number").unwrap().to_string()),
            country_id: account_doc
                .get_str("country_id")
                .unwrap_or("en-qreeket-233")
                .to_string(),
            language_id: language_id.to_string(),
            created_at: _parse_timestamp_field(account_doc.get("created_at").unwrap()),
            updated_at: _parse_timestamp_field(account_doc.get("updated_at").unwrap()),
            avatar_url: Some(account_doc.get_str("avatar_url").unwrap_or("").to_string()),
            college_id: account_doc.get_str("college_id").unwrap().to_string(),
            username: account_doc
                .get_str("username")
                .unwrap_or("")
                .to_string(),
            device_id: Some(
                account_doc
                    .get_str("device_id")
                    .unwrap_or("")
                    .to_string(),
            ),
            device_type: Some(
                account_doc
                    .get_str("device_type")
                    .unwrap_or("")
                    .to_string(),
            ),
            device_token: Some(
                account_doc
                    .get_str("device_token")
                    .unwrap_or("")
                    .to_string(),
            ),
            is_verified: Some(account_doc.get_bool("is_verified").unwrap_or(false)),
            user_type: Some(
                i32::from(UserType::from_i32(account_doc.get_i32("user_type").unwrap_or(0)).unwrap()),
            ),
            email: Some(account_doc.get_str("email").unwrap_or("").to_string()),
            is_visible: Some(account_doc.get_bool("email").unwrap_or(true)),
        };

        Ok(Response::new(account))
    }

    // done
    async fn get_account_by_phone_number(
        &self,
        request: Request<String>,
    ) -> Result<Response<Account>, Status> {
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // verify public token
        match config::session_manager::verify_public_access_token(&request.metadata(), &language_id)
            .await
        {
            Ok(_) => (),
            Err(e) => {
                return Err(e);
            }
        };

        // find account by phone number
        let phone_number = request.into_inner();
        let account_doc = match self
            .account_col
            .find_one(doc! {"phone_number": &phone_number}, None)
            .await
            .unwrap()
        {
            Some(acct_doc) => acct_doc,
            None => {
                return Err(Status::not_found(t!("account_not_found")));
            }
        };

        // create account object from account doc
        let account = Account {
            id: account_doc.get_str("id").unwrap().to_string(),
            country_id: account_doc.get_str("country_id").unwrap().to_string(),
            phone_number: Some(account_doc.get_str("phone_number").unwrap().to_string()),
            language_id: language_id.to_string(),
            college_id: account_doc.get_str("college_id").unwrap().to_string(),
            created_at: _parse_timestamp_field(account_doc.get("created_at").unwrap()),
            updated_at: _parse_timestamp_field(account_doc.get("updated_at").unwrap()),
            avatar_url: Some(account_doc.get_str("avatar_url").unwrap_or("").to_string()),
            username: account_doc
                .get_str("username")
                .unwrap_or("")
                .to_string(),
            device_id: Some(
                account_doc
                    .get_str("device_id")
                    .unwrap_or("")
                    .to_string(),
            ),
            device_type: Some(
                account_doc
                    .get_str("device_type")
                    .unwrap_or("")
                    .to_string(),
            ),
            device_token: Some(
                account_doc
                    .get_str("device_token")
                    .unwrap_or("")
                    .to_string(),
            ),
            is_verified: Some(account_doc.get_bool("is_verified").unwrap_or(false)),
            user_type: Some(
                i32::from(UserType::from_i32(account_doc.get_i32("user_type").unwrap_or(0)).unwrap()),
            ),
            email: Some(account_doc.get_str("email").unwrap_or("").to_string()),
            is_visible: Some(account_doc.get_bool("email").unwrap_or(true)),
        };

        Ok(Response::new(account))
    }

    async fn get_account_by_id(&self, request: Request<String>) -> Result<Response<Account>, Status> {
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // verify public token
        match config::session_manager::verify_access_token(&request.metadata(), &language_id, &self.token_col)
            .await
        {
            Ok(_) => (),
            Err(e) => {
                return Err(e);
            }
        };

        // find account by id
        let id = request.into_inner();
        let account_doc = match self
            .account_col
            .find_one(doc! {"id": &id}, None)
            .await
            .unwrap()
        {
            Some(acct_doc) => acct_doc,
            None => {
                return Err(Status::not_found(t!("account_not_found")));
            }
        };

        // create account object from account doc
        let account = Account {
            id: account_doc.get_str("id").unwrap().to_string(),
            country_id: account_doc.get_str("country_id").unwrap().to_string(),
            phone_number: Some(account_doc.get_str("phone_number").unwrap().to_string()),
            language_id: language_id.to_string(),
            college_id: account_doc.get_str("college_id").unwrap().to_string(),
            created_at: _parse_timestamp_field(account_doc.get("created_at").unwrap()),
            updated_at: _parse_timestamp_field(account_doc.get("updated_at").unwrap()),
            avatar_url: Some(account_doc.get_str("avatar_url").unwrap_or("").to_string()),
            username: account_doc
                .get_str("username")
                .unwrap_or("")
                .to_string(),
            device_id: Some(
                account_doc
                    .get_str("device_id")
                    .unwrap_or("")
                    .to_string(),
            ),
            device_type: Some(
                account_doc
                    .get_str("device_type")
                    .unwrap_or("")
                    .to_string(),
            ),
            device_token: Some(
                account_doc
                    .get_str("device_token")
                    .unwrap_or("")
                    .to_string(),
            ),
            is_verified: Some(account_doc.get_bool("is_verified").unwrap_or(false)),
            user_type: Some(
                i32::from(UserType::from_i32(account_doc.get_i32("user_type").unwrap_or(0)).unwrap()),
            ),
            email: Some(account_doc.get_str("email").unwrap_or("").to_string()),
            is_visible: Some(account_doc.get_bool("email").unwrap_or(true)),
        };

        Ok(Response::new(account))
    }

    // done
    async fn update_account(&self, request: Request<Account>) -> Result<Response<Account>, Status> {
        // validate language id
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // verify access token using tokenizer
        match config::session_manager::verify_access_token(
            &request.metadata(),
            &language_id,
            &self.token_col,
        )
            .await
        {
            Ok(token) => token,
            Err(e) => {
                return Err(e);
            }
        };

        // extract account object from request
        let account = request.into_inner();

        // perform account update with account object from request
        match self
            .account_col
            .find_one_and_update(
                doc! {"id": &account.id},
                doc! {"$set": {
                    "username": &account.username,
                    "avatar_url": &account.avatar_url.unwrap(),
                    "user_type": &account.user_type.unwrap(),
                    "updated_at": _create_timestamp_field(),
                    "country_id" : &account.country_id,
                    "device_id" : &account.device_id.unwrap(),
                    "device_type" : &account.device_type.unwrap(),
                    "device_token" : &account.device_token.unwrap(),
                    "is_verified" : &account.is_verified.unwrap(),
                }},
                None,
            )
            .await
            .unwrap()
        {
            Some(acct_doc) => acct_doc,
            None => {
                return Err(Status::not_found(t!("account_not_found")));
            }
        };

        // get the updated account document
        let account_doc = match self
            .account_col
            .find_one(doc! {"id": &account.id}, None)
            .await
            .unwrap()
        {
            Some(acct_doc) => acct_doc,
            None => {
                return Err(Status::not_found(t!("account_not_found")));
            }
        };

        // create account object to return
        let account = Account {
            id: account_doc.get_str("id").unwrap().to_string(),
            country_id: account_doc.get_str("country_id").unwrap().to_string(),
            phone_number: Some(account_doc.get_str("phone_number").unwrap().to_string()),
            created_at: _parse_timestamp_field(account_doc.get("created_at").unwrap()),
            updated_at: _parse_timestamp_field(account_doc.get("updated_at").unwrap()),
            avatar_url: Some(account_doc.get_str("avatar_url").unwrap_or("").to_string()),
            college_id: account_doc.get_str("college_id").unwrap().to_string(),
            username: account_doc
                .get_str("username")
                .unwrap_or("")
                .to_string(),
            user_type: Some(
                i32::from(UserType::from_i32(account_doc.get_i32("user_type").unwrap_or(0)).unwrap()),
            ),
            language_id,
            email: Some(
                account_doc
                    .get_str("email")
                    .unwrap_or("")
                    .to_string(),
            ),
            device_id: Some(
                account_doc
                    .get_str("device_id")
                    .unwrap_or("")
                    .to_string(),
            ),
            device_type: Some(
                account_doc
                    .get_str("device_type")
                    .unwrap_or("")
                    .to_string(),
            ),
            device_token: Some(
                account_doc
                    .get_str("device_token")
                    .unwrap_or("")
                    .to_string(),
            ),
            is_verified: Some(account_doc.get_bool("is_verified").unwrap_or(false)),
            is_visible: Some(account_doc.get_bool("email").unwrap_or(true)),
        };

        Ok(Response::new(account))
    }

    // done
    async fn delete_account(&self, request: Request<()>) -> Result<Response<()>, Status> {
        // validate language id
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // verify access token using tokenizer
        let token = match config::session_manager::verify_access_token(
            &request.metadata(),
            &language_id,
            &self.token_col,
        )
            .await
        {
            Ok(token) => token,
            Err(e) => {
                return Err(e);
            }
        };

        // delete token from token collection
        let oid = bson::oid::ObjectId::parse_str(&token.0).unwrap();
        match self
            .token_col
            .delete_one(doc! {"_id": oid}, None)
            .await
        {
            Ok(_) => (),
            Err(_) => {
                return Err(Status::not_found(t!("token_not_found")));
            }
        };

        // delete account using account id from token payload
        match self
            .account_col
            .delete_one(doc! {"id": &token.0}, None)
            .await
        {
            Ok(_) => Ok(Response::new(())),
            Err(_) => {
                return Err(Status::not_found(t!("account_not_found")));
            }
        }
    }

    // done
    async fn authenticate_account(&self, request: Request<AuthenticateWithSocialAccountRequest>) -> Result<Response<String>, Status> {
        // validate language id
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // verify access token using tokenizer
        match config::session_manager::verify_public_access_token(
            &request.metadata(),
            &language_id,
        ).await
        {
            Ok(_) => (),
            Err(e) => {
                return Err(e);
            }
        };

        let req = request.into_inner();
        let email = &req.email;

        // check account_col if email already exists
        let account_doc = match self
            .account_col
            .find_one(doc! {"email": &email}, None)
            .await
            .unwrap()
        {
            Some(acct_doc) => Some(acct_doc),
            None => None,
        };

        // if account exists, generate access token and return it
        return if account_doc.is_some() {
            let account_doc = account_doc.unwrap();
            let account_id = account_doc.get_str("id").unwrap().to_string();
            let access_token = match config::session_manager::create_access_token(
                &account_id,
                &language_id,
                &self.token_col,
            )
                .await {
                Ok(access_token) => access_token,
                Err(err) => {
                    error!("Error creating access token: {}", err);
                    return Err(Status::internal(t!("auth_failed")));
                }
            };
            Ok(Response::new(access_token))
        } else {
            if !req.country_id.is_empty() && !req.college_id.is_empty() {
                let avatar = match req.auth_avatar {
                    Some(avatar_url) => {
                        match avatar_url {
                            AuthAvatar::AvatarData(avatar) => match _upload_media(&avatar, &req.phone_number, "avatar").await {
                                Ok(avatar) => avatar,
                                Err(_) => "".to_string(),
                            },
                            AuthAvatar::AvatarUrl(url) => url,
                        }
                    }
                    None => "".to_string(),
                };
                println!("avatar: {}", avatar);

                let mut account_doc = doc! {
                    "phone_number" : &req.phone_number,
                    "username" : &req.username,
                    "language_id" : &language_id,
                    "created_at": _create_timestamp_field(),
                    "updated_at": _create_timestamp_field(),    // aka: last login
                    "avatar_url" : avatar,
                    "password" : "".to_string(),
                    "country_id" : &req.country_id,
                    "is_verified" : Some(false),
                    "college_id" : &req.college_id,
                    "email" : &email,
                    "device_id" : "",
                    "device_token" : "",
                    "device_type" : "",
                    "user_type" : UserType::Standard as i32,
                 };


                // save account to db
                return match self
                    .account_col
                    .insert_one(&account_doc.clone(), None)
                    .await
                {
                    Ok(result) => {
                        // update id field with result
                        account_doc.insert("id", &result.inserted_id.as_object_id().unwrap().to_hex());

                        // replace one in db with updated account doc
                        match self
                            .account_col
                            .replace_one(doc! {"email": &email}, &account_doc, None)
                            .await
                        {
                            Ok(_) => (),
                            Err(_) => {
                                return Err(Status::internal(t!("auth_failed")));
                            }
                        }

                        // create a new access token
                        let access_token = config::session_manager::create_access_token(
                            &account_doc.get_str("id").unwrap().to_string(),
                            &language_id,
                            &self.token_col,
                        )
                            .await
                            .unwrap();
                        Ok(Response::new(access_token))
                    }
                    Err(_) => {
                        Err(Status::internal(t!("auth_failed")))
                    }
                };
            }

            Err(Status::not_found(t!("account_not_found")))
        };
    }

    // done
    async fn check_email(&self, request: Request<String>) -> Result<Response<()>, Status> {
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // verify public token
        match config::session_manager::verify_public_access_token(&request.metadata(), &language_id)
            .await
        {
            Ok(_) => (),
            Err(e) => {
                return Err(e);
            }
        };

        // find account by email
        let email = request.into_inner();

        match self.account_col.find_one(doc! {"email": &email}, None).await.unwrap() {
            Some(_) => {
                Err(Status::already_exists(t!("email_already_exists")))
            }
            None => Ok(Response::new(())),
        }
    }

    // done
    async fn check_phone_number(&self, request: Request<String>) -> Result<Response<()>, Status> {
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // verify public token
        match config::session_manager::verify_public_access_token(&request.metadata(), &language_id)
            .await
        {
            Ok(_) => (),
            Err(e) => {
                return Err(e);
            }
        };

        // find account by phone number
        let phone_number = request.into_inner();

        match self.account_col.find_one(doc! {"phone_number": &phone_number}, None).await.unwrap() {
            Some(_) => {
                Err(Status::already_exists(t!("phone_number_already_exists")))
            }
            None => Ok(Response::new(())),
        }
    }

    // done
    async fn get_countries(
        &self,
        request: Request<()>,
    ) -> Result<Response<GetCountriesResponse>, Status> {
        // validate language id
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // validate access token
        let is_guest = match config::session_manager::verify_public_access_token(&request.metadata(), &language_id)
            .await
        {
            Ok(_) => true,
            Err(_) => false,
        };
        if !is_guest {
            match config::session_manager::verify_access_token(&request.metadata(), &language_id, &self.token_col).await {
                Ok(token) => token.0,
                Err(e) => {
                    return Err(e);
                }
            };
        }

        // get countries from database
        let opts = FindOptions::builder().sort(doc! {"name": 1}).build();
        let mut cursor = match self.country_col.find(None, opts).await {
            Ok(countries) => countries,
            Err(_) => {
                return Err(Status::not_found(t!("countries_not_found")));
            }
        };

        // create countries vector
        let mut countries = vec![];

        // iterate through cursor
        while let Some(result) = cursor.next().await {
            match result {
                Ok(document) => {
                    let country = Country {
                        id: document.get_str("id").unwrap().to_string(),
                        name: document.get_str("name").unwrap().to_string(),
                        code: document.get_str("code").unwrap().to_string(),
                        dial_code: document.get_str("dial_code").unwrap().to_string(),
                        currency: document.get_str("currency").unwrap().to_string(),
                        currency_symbol: document.get_str("currency_symbol").unwrap().to_string(),
                        flag_url: document.get_str("flag_url").unwrap().to_string(),
                        language_id: document.get_str("language_id").unwrap().to_string(),
                    };
                    countries.push(country);
                }
                Err(_) => return Err(Status::internal(t!("countries_not_found"))),
            }
        }

        // create response
        let response = GetCountriesResponse { countries };

        Ok(Response::new(response))
    }

    // done
    async fn get_country_by_id(
        &self,
        request: Request<String>,
    ) -> Result<Response<Country>, Status> {
        // validate language id
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // validate access token
        match config::session_manager::verify_access_token(
            &request.metadata(),
            &language_id,
            &self.token_col,
        )
            .await
        {
            Ok(token) => token,
            Err(e) => {
                return Err(e);
            }
        };

        // get country id from request
        let country_id = request.into_inner();

        // get country from database
        let country_doc = match self
            .country_col
            .find_one(doc! {"id": &country_id}, None)
            .await
            .unwrap()
        {
            Some(country_doc) => country_doc,
            None => {
                return Err(Status::not_found(t!("country_not_found")));
            }
        };

        // create country
        let country = Country {
            id: country_doc.get_str("id").unwrap().to_string(),
            name: country_doc.get_str("name").unwrap().to_string(),
            code: country_doc.get_str("code").unwrap().to_string(),
            dial_code: country_doc.get_str("dial_code").unwrap().to_string(),
            currency: country_doc.get_str("currency").unwrap().to_string(),
            currency_symbol: country_doc.get_str("currency_symbol").unwrap().to_string(),
            flag_url: country_doc.get_str("flag_url").unwrap().to_string(),
            language_id: country_doc.get_str("language_id").unwrap().to_string(),
        };

        Ok(Response::new(country))
    }

    // done
    async fn add_country(&self, request: Request<Country>) -> Result<Response<Country>, Status> {
        // validate language id
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // validate access token
        match config::session_manager::verify_public_access_token(&request.metadata(), &language_id)
            .await
        {
            Ok(token) => token,
            Err(e) => {
                return Err(e);
            }
        };

        // get country from request
        let mut country = request.into_inner();

        // check if country already exists
        match self
            .country_col
            .find_one(doc! {"code": &country.code}, None)
            .await
            .unwrap()
        {
            Some(_) => {
                return Err(Status::already_exists(t!("country_already_exists")));
            }
            None => (),
        };

        // create country document
        let re = Regex::new(r"[^a-zA-Z0-9\s]+").unwrap();
        let id_builder = re.replace_all(&country.dial_code, "").to_string();
        country.id = format!(
            "{}-{}-{}",
            &country.code.to_lowercase(),
            utils::generators::generate_random_string(17),
            id_builder
        )
            .to_string();
        let country_doc = doc! {
            "id": &country.id,
            "name": &country.name,
            "code": &country.code,
            "dial_code": &country.dial_code,
            "currency": &country.currency,
            "currency_symbol": &country.currency_symbol,
            "flag_url": &country.flag_url,
            "language_id": &country.language_id,
        };

        // insert country into database
        match self.country_col.insert_one(country_doc, None).await {
            Ok(_) => {
                // get country from database
                let country_doc = match self
                    .country_col
                    .find_one(doc! {"id": &country.id}, None)
                    .await
                    .unwrap()
                {
                    Some(country_doc) => country_doc,
                    None => {
                        return Err(Status::not_found(t!("country_not_found")));
                    }
                };

                // create country
                country = Country {
                    id: country_doc.get_str("id").unwrap().to_string(),
                    name: country_doc.get_str("name").unwrap().to_string(),
                    code: country_doc.get_str("code").unwrap().to_string(),
                    dial_code: country_doc.get_str("dial_code").unwrap().to_string(),
                    currency: country_doc.get_str("currency").unwrap().to_string(),
                    currency_symbol: country_doc.get_str("currency_symbol").unwrap().to_string(),
                    flag_url: country_doc.get_str("flag_url").unwrap().to_string(),
                    language_id: country_doc.get_str("language_id").unwrap().to_string(),
                };

                Ok(Response::new(country.to_owned()))
            }
            Err(_) => {
                Err(Status::internal(t!("country_not_added")))
            }
        }
    }

    // done
    async fn delete_country(&self, request: Request<String>) -> Result<Response<()>, Status> {
        // validate language id
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // validate access token
        match config::session_manager::verify_public_access_token(&request.metadata(), &language_id)
            .await
        {
            Ok(token) => token,
            Err(e) => {
                return Err(e);
            }
        };

        // get country id from request
        let country_id = request.into_inner();

        // delete country from database
        match self
            .country_col
            .delete_one(doc! {"id": &country_id}, None)
            .await
        {
            Ok(_) => Ok(Response::new(())),
            Err(_) => {
                Err(Status::internal(t!("country_not_deleted")))
            }
        }
    }

    // done
    async fn get_colleges_for_country(&self, request: Request<String>) -> Result<Response<GetCollegesResponse>, Status> {
        // validate language id
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // validate access token
        let is_guest = match config::session_manager::verify_public_access_token(&request.metadata(), &language_id)
            .await
        {
            Ok(_) => true,
            Err(_) => false,
        };
        if !is_guest {
            match config::session_manager::verify_access_token(&request.metadata(), &language_id, &self.token_col).await {
                Ok(token) => token.0,
                Err(e) => {
                    return Err(e);
                }
            };
        }

        // get countries from database
        let opts = FindOptions::builder().sort(doc! {"name": 1}).build();
        let mut cursor = match self.college_col.find(doc! {"country_id":  &request.into_inner()}, opts).await {
            Ok(colleges) => colleges,
            Err(_) => {
                return Err(Status::not_found(t!("colleges_not_found")));
            }
        };

        // create colleges vector
        let mut colleges = vec![];

        // iterate through cursor
        while let Some(result) = cursor.next().await {
            match result {
                Ok(document) => {
                    let college = College {
                        id: document.get_str("id").unwrap().to_string(),
                        name: document.get_str("name").unwrap().to_string(),
                        country_id: document.get_str("country_id").unwrap().to_string(),
                        address: document.get_str("address").unwrap().to_string(),
                        website: document.get_str("website").unwrap().to_string(),
                        logo_url: document.get_str("logo_url").unwrap().to_string(),
                        banner_url: Some(document.get_str("banner_url").unwrap_or("").to_string()),
                    };
                    colleges.push(college);
                }
                Err(_) => return Err(Status::internal(t!("colleges_not_found"))),
            }
        }

        // create response
        let response = GetCollegesResponse { colleges };

        Ok(Response::new(response))
    }

    // done
    async fn get_college_by_id(&self, request: Request<String>) -> Result<Response<College>, Status> {
        // validate language id
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // validate access token
        match config::session_manager::verify_access_token(
            &request.metadata(),
            &language_id,
            &self.token_col,
        )
            .await
        {
            Ok(token) => token,
            Err(e) => {
                return Err(e);
            }
        };

        // get college id from request
        let college_id = request.into_inner();

        // get college from database
        let college_doc = match self
            .college_col
            .find_one(doc! {"id": &college_id}, None)
            .await
            .unwrap()
        {
            Some(college_doc) => college_doc,
            None => {
                return Err(Status::not_found(t!("college_not_found")));
            }
        };

        // create college
        let college = College {
            id: college_doc.get_str("id").unwrap().to_string(),
            name: college_doc.get_str("name").unwrap().to_string(),
            country_id: college_doc.get_str("country_id").unwrap().to_string(),
            address: college_doc.get_str("address").unwrap().to_string(),
            website: college_doc.get_str("website").unwrap().to_string(),
            logo_url: college_doc.get_str("logo_url").unwrap().to_string(),
            banner_url: Some(college_doc.get_str("banner_url").unwrap_or("").to_string()),
        };

        Ok(Response::new(college))
    }

    // done
    async fn add_college(&self, request: Request<College>) -> Result<Response<College>, Status> {
        // validate language id
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // validate access token
        match config::session_manager::verify_public_access_token(&request.metadata(), &language_id)
            .await
        {
            Ok(token) => token,
            Err(e) => {
                return Err(e);
            }
        };

        // get college from request
        let mut college = request.into_inner();

        // check if college already exists
        match self
            .college_col
            .find_one(doc! {"name": &college.name}, None)
            .await
            .unwrap()
        {
            Some(_) => {
                return Err(Status::already_exists(t!("college_already_exists")));
            }
            None => (),
        };

        // create college document
        college.id = utils::generators::generate_random_string(24).to_string();

        let college_doc = doc! {
            "id": &college.id,
            "name": &college.name,
            "website": &college.website,
            "logo_url": &college.logo_url,
            "country_id": &college.country_id,
            "address": &college.address,
            "banner_url" : &college.banner_url,
        };

        // insert college into database
        match self.college_col.insert_one(college_doc, None).await {
            Ok(_) => {
                // get college from database
                let college_doc = match self
                    .college_col
                    .find_one(doc! {"id": &college.id}, None)
                    .await
                    .unwrap()
                {
                    Some(college_doc) => college_doc,
                    None => {
                        return Err(Status::not_found(t!("college_not_found")));
                    }
                };

                // create college
                college = College {
                    id: college_doc.get_str("id").unwrap().to_string(),
                    name: college_doc.get_str("name").unwrap().to_string(),
                    country_id: college_doc.get_str("country_id").unwrap().to_string(),
                    address: college_doc.get_str("address").unwrap().to_string(),
                    website: college_doc.get_str("website").unwrap().to_string(),
                    logo_url: college_doc.get_str("logo_url").unwrap().to_string(),
                    banner_url: Some(college_doc.get_str("banner_url").unwrap_or("").to_string()),
                };

                Ok(Response::new(college.to_owned()))
            }
            Err(_) => {
                Err(Status::internal(t!("college_not_added")))
            }
        }
    }

    // done
    async fn delete_college(&self, request: Request<String>) -> Result<Response<()>, Status> {
        // validate language id
        let language_id = match _validate_language_id_from_request(request.metadata()) {
            Ok(language_id) => language_id,
            Err(e) => {
                return Err(e);
            }
        };

        // validate access token
        match config::session_manager::verify_public_access_token(&request.metadata(), &language_id)
            .await
        {
            Ok(token) => token,
            Err(e) => {
                return Err(e);
            }
        };

        // get college id from request
        let college_id = request.into_inner();

        // delete college from database
        match self
            .college_col
            .delete_one(doc! {"id": &college_id}, None)
            .await
        {
            Ok(_) => Ok(Response::new(())),
            Err(_) => {
                Err(Status::internal(t!("college_not_deleted")))
            }
        }
    }
}

// create timestamp field
#[inline]
fn _create_timestamp_field() -> String {
    Utc::now().to_rfc3339()
}

// parse timestamp field
fn _parse_timestamp_field(timestamp: &Bson) -> Option<prost_types::Timestamp> {
    let parsed = match DateTime::parse_from_rfc3339(timestamp.as_str().unwrap()) {
        Ok(result) => result,
        Err(_) => {
            return None;
        }
    };
    Some(prost_types::Timestamp {
        seconds: parsed.timestamp_millis(),
        nanos: 0,
    })
}

// validate language id
fn _validate_language_id_from_request(md: &MetadataMap) -> Result<String, Status> {
    let language_id = match md.get("x-language-id") {
        Some(result) => result.to_str().unwrap().to_string(),
        None => {
            return Err(Status::invalid_argument(t!("invalid_language_code")));
        }
    };
    // validate language id from request
    match locale::validate_language_id(&language_id) {
        Ok(_) => {
            rust_i18n::set_locale(&language_id);
            Ok(language_id)
        }
        Err(_) => {
            return Err(Status::invalid_argument(t!("invalid_language_code")));
        }
    }
}

// get authentication type from metadata
fn _get_authentication_type_from_metadata(md: &MetadataMap) -> Result<bool, Status> {
    let authentication_type = match md.get("x-authenticated") {
        Some(result) => result.to_str().unwrap().to_string(),
        None => {
            return Err(Status::invalid_argument(t!("invalid_token")));
        }
    };
    Ok(authentication_type == "true")
}

// upload base64 avatar using media client
async fn _upload_media(encoded_string: &Vec<u8>, identifier: &str, name: &str) -> Result<String, Box<dyn Error>> {
    // get client
    let mut client = match client::get_media_client().await {
        Ok(client) => client,
        Err(e) => {
            return Err(format!("{}: {:?}", t!("media_not_uploaded"), e).into());
        }
    };

    // upload media
    let request = UploadMediaRequest {
        name: Some(name.to_string()),
        media: encoded_string.to_vec(),
        owner: Some(identifier.to_string()),
        r#type: MediaType::Image as i32,
    };
    match client.upload_media(request).await {
        Ok(response) => Ok(response.into_inner().url),
        Err(e) => Err(format!("{}: {:?}", t!("media_not_uploaded"), e).into())
    }
}