use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use warp::{self,Filter};
use serde::{Deserialize, Serialize};
use bcrypt::{hash, verify, DEFAULT_COST};
use warp::http::StatusCode;
use warp::reject::{Rejection, Reject};
use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
use jsonwebtoken::errors::Result as JWTResult;

#[derive(Debug)]
struct CustomError(String);

impl Reject for CustomError {}

fn custom_error(msg: &str) -> warp::Rejection {
    warp::reject::custom(CustomError(msg.to_string()))
}


#[derive(Serialize,Deserialize)]
struct User {
    email: String,
    password: String,
    city: String,
    phone: String,
    uid: i128,
    //other user fields
}

//JWT token claims - Sub is user id, exp is expiration
#[derive(Serialize,Deserialize)]
struct Claims{
    sub:String,
    exp:usize,
}

//mock database
type Db = Arc<Mutex<HashMap<i128,User>>>;

#[tokio::main]
async fn main(){

let db: Db = Arc::new(Mutex::new(HashMap::new()));

let register_route = warp::post()
    .and(warp::path("register"))
    .and(warp::body::json())
    .and(with_db(db.clone())) 
    .and_then(register_handler);

let login_route = warp::post()
    .and(warp::path("login"))
    .and(warp::body::json())
    .and(with_db(db.clone()))
    .and_then(login_handler);
let routes = register_route.or(login_route);

warp::serve(routes).run(([0, 0, 0, 0], 8000)).await;
}

//Handles User Registration Requests
async fn register_handler(user: User, db: Db) -> Result<impl warp::Reply, warp::Rejection> {
    let hashed_password = hash(&user.password, DEFAULT_COST)
        .map_err(|_|custom_error("Hashing failed"))?;
    let mut user = user;
    user.password = hashed_password;

    //TODO: Check if email already exists, if yes return error, else insert into db
    //TODO: Generate unique user id
    
    let mut map = db.lock().unwrap();
    map.insert(user.uid.clone(), user);

    Ok(warp::reply::json(&"Registered successfully"))
}

//Handles User Login Requests
async fn login_handler(user: User, db: Db) -> Result<impl warp::Reply, warp::Rejection> {
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

fn generate_token(claims: Claims) -> JWTResult<String> {
    let key = "secret".as_ref(); // Replace with your actual secret key
    encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(key))
}

fn with_db(db: Arc<Mutex<HashMap<i128, User>>>) -> impl Filter<Extract = (Arc<Mutex<HashMap<i128, User>>>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || db.clone())
}