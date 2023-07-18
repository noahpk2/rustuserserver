use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use alloc::collections;
use warp::{self,Filter};
use serde::{Deserialize, Serialize};
use bcrypt::{hash, verify, DEFAULT_COST};
use mongodb::{Client, options::ClientOptions};
use warp::http::StatusCode;
use warp::reject::{Rejection, Reject};
use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
use jsonwebtoken::errors::Result as JWTResult;

//Custom error type for rejecting requests with custom error messages... for some reason, I couldn't get the default warp::reject::Rejection to work.
#[derive(Debug)]
struct CustomError(String);

impl Reject for CustomError {}

fn custom_error(msg: &str) -> warp::Rejection {
    warp::reject::custom(CustomError(msg.to_string()))
}

//User struct - containes user fields that will be stored in the database
#[derive(Serialize,Deserialize)]
struct User {
    email: String,
    password: String,
    location: String,
    phone: String,
    uid: uuid::Uuid,
    //other user fields
}

struct Collections{
    users: mongodb::Collection,
    events: mongodb::Collection,
}

//JWT token claims - Sub is user id, exp is expiration
//A JWT token is generated when a user logs in successfully and is sent to the client
#[derive(Serialize,Deserialize)]
struct Claims{
    sub:String,
    exp:usize,
}

//mock database
// TODO: Replace with actual database(s) - mongodb and neo4j
type Db = Arc<Mutex<HashMap<i128,User>>>;


//Main function - starts the server and defines the routes for the api
#[tokio::main]
async fn main(){

let userDB: Db = Arc::new(Mutex::new(HashMap::new()));

let client_options = mongodb::options::ClientOptions::parse("mongodb://localhost:27017").await.unwrap();
client_options.app_name = Some("RustUserServer".to_string());

let client = mongodb::Client::with_options(client_options).unwrap();

let db = client.database("concertbuddy");
let users_collection = db.collection("users");
let events_collection = db.collection("events");

let collections = Collections{
    users: users_collection,
    events: events_collection,
};



//User registration route
let register_route = warp::post()
    .and(warp::path("register"))
    .and(warp::body::json())
    .and(with_db(collections.clone())) 
    .and_then(register_handler);
//User login route
let login_route = warp::post()
    .and(warp::path("login"))
    .and(warp::body::json())
    .and(with_db(collections.clone()))
    .and_then(login_handler);
//TODO: Add other routes (user profile, user search, etc.)

//Combine all routes
let routes = register_route.or(login_route);

//Start server
warp::serve(routes).run(([0, 0, 0, 0], 8000)).await;
}





//Handles User Registration Requests
async fn register_handler(user: User, collections: Collections) -> Result<impl warp::Reply, warp::Rejection> {
    let hashed_password = hash(&user.password, DEFAULT_COST)
        .map_err(|_|custom_error("Hashing failed"))?;
    let mut user = user;
    user.password = hashed_password;

    //TODO: Check if email or user id already exists, if yes return error, else insert into db


    //TODO: Generate unique user id

    let mut map = db.lock().unwrap();
    map.insert(user.uid.clone(), user);

    Ok(warp::reply::json(&"Registered successfully"))
}

//Handles User Login Requests
async fn login_handler(user: User, collections: Collections) -> Result<impl warp::Reply, warp::Rejection> {
    let map = db.lock().unwrap();
    match map.get(&user.uid) {
        Some(stored_user) => {
            // Compare hashed passwords
            if verify(&user.password, &stored_user.password)
                .map_err(|_| custom_error("Verification failed"))? {
                let claims = Claims {
                    sub: user.email.clone(),
                    // Replace with the actual expiration time
                    exp: 10000000000,
                };
                match generate_token(claims) {
                    Ok(token) => Ok(warp::reply::json(&token)),
                    Err(_) => Ok(warp::reply::json(&"Token generation failed")),
                }
            } else {
                Ok(warp::reply::json(&"Invalid email or password"))
            }
        }
        None => Ok(warp::reply::json(&"Invalid email or password")),
    }
}

async fn create_event_handler(event: Event, collections: Collections) -> Result<impl warp::Reply, warp::Rejection> {
}

fn generate_token(claims: Claims) -> JWTResult<String> {
    let key = "secret".as_ref(); // Replace with your actual secret key
    encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(key))
}

//Helper function to pass the database to the handlers, since warp doesn't support passing state to handlers.
fn with_db(collections: Collections) -> impl Filter<Extract = (Collections), Error = std::convert::Infallible> + Clone{
    warp::any().map(move || collections.clone())
}