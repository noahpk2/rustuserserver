extern crate uuid;

use mongodb::bson::doc;
use uuid::Uuid;
use warp::{self,Filter};
use serde::{Deserialize, Serialize};
use bcrypt::{hash, verify, DEFAULT_COST};
use mongodb::{Client, options::ClientOptions};
use warp::http::StatusCode;
use warp::reject::{Rejection, Reject};
use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
use jsonwebtoken::errors::Result as JWTResult;

/**Custom error type for rejecting requests with custom error messages... for some reason, I couldn't get the default warp::reject::Rejection to work.*/
#[derive(Debug)]
struct CustomError(String);
impl Reject for CustomError {}
fn custom_error(msg: &str) -> warp::Rejection {
    warp::reject::custom(CustomError(msg.to_string()))
}

/**User struct - containes user fields that will be stored in the database
 * 
 * 
*/

#[derive(Serialize,Deserialize,Debug)]
struct User {
    email: String,
    password_hash: String,
    location: String,
    phone: String,
    uid: uuid::Uuid,
    //other user fields
}

/**
 * LoginRequest struct - contains fields that will be sent in a user login request
 */
#[derive(Serialize,Deserialize)]
struct LoginRequest {
    email: String,
    password_hash: String,
}

/**
 * RegisterRequest struct - contains fields that will be sent in a user registration request
 * # Parameters:
 * * email: String
 * * password_hash: String
 * * name: String
 * * date_of_birth: String
 * * location: String
 * * phone: String
 * # TODO: Add other user fields?
 */
#[derive(Serialize,Deserialize)]
struct RegisterRequest {
    email: String,
    password_hash: String,
    name: String,
    date_of_birth: String,
    location: String,
    phone: String,
}

/**
 * Event struct - contains event fields that will be stored in the database
 * # Parameters:
 * * name: String
 * * location: String
 * * date: String
 * * time: String
 * * description: String
 * # TODO: Add other event fields?
 */
struct Event {
    name: String,
    location: String,
    date: String,
    time: String,
    description: String,
    //other event fields
}


/**
 * Collections struct - contains mongodb collections that will be used to store users and events
 * # Parameters:
 * * users: mongodb::Collection<User>
 * * events: mongodb::Collection<Event>
 * # TODO: Add other collections?
 */

#[derive(Clone)]
struct Collections{
    users: mongodb::Collection<User>,
    events: mongodb::Collection<Event>,
}

/**
 * Claims struct - contains fields that will be used to generate a JWT token for maintaining user sessions
 */
#[derive(Serialize,Deserialize)]
struct Claims{
    sub:String,
    exp:usize,
}


/**
 * # Main function 
 * * tokio server
 * * Uses warp to create routes and handle requests
 * Uses mongodb driver to connect to the database
 * 
 */
#[tokio::main]
async fn main(){

let mut client_options = mongodb::options::ClientOptions::parse("mongodb://localhost:27017").await.unwrap();
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

//TODO: Add authentication middleware

//TODO: Add error handling middleware




//Combine all routes
let routes = register_route.or(login_route);

//Start server
warp::serve(routes).run(([0, 0, 0, 0], 8000)).await;
}





//Handles User Registration Requests
async fn register_handler(request: RegisterRequest, collections: Collections) -> Result<impl warp::Reply, warp::Rejection> {
    
    let hashed_password = hash(&request.password_hash, DEFAULT_COST)
        .map_err(|_|custom_error("Hashing failed"))?;

    // 1. Search for user with email
    let filter = doc! {"email": &request.email};
    let user_check = collections.users.find_one(filter.clone(), None).await;

    //2. If user with email exists, return error
    if let Ok(Some(_)) = user_check {
        return Ok(warp::reply::json(&"User with this email already exists"));
    }

    //3. If user with email doesn't exist, insert into db
    let new_user = User{
        email: request.email,
        password_hash: hashed_password,
        location: request.location,
        phone: request.phone,
        uid: Uuid::new_v4(),
    };

    let user_doc = mongodb::bson::to_document(&new_user)
    .map_err(|_| custom_error("Failed to convert user to document"))?;
    
    // Insert the new user into the database
    let _ = collections.users.insert_one(new_user, None).await
        .map_err(|_| custom_error("Failed to insert new user"))?;

    Ok(warp::reply::json(&"Registered successfully"))
}




/**
 * # Handles User Login Requests
 * 
 * 
 */
async fn login_handler(request: LoginRequest, collections: Collections) -> Result<impl warp::Reply, warp::Rejection> {
    
    // 1. Search for user with email
    let filter = doc! {"email": &request.email};

    let stored_user_doc_option: Result<Option<mongodb::bson::Document>, _> = Err(collections.users.find_one(filter, None).await);

    match stored_user_doc_option{

        Ok(Some(stored_user_doc)) => {
            
            match mongodb::bson::from_document::<User>(stored_user_doc){
                Ok(stored_user) =>{
                    

                    //2. If user with email exists, verify password
                    let password_matches = verify(&request.password_hash, &stored_user.password_hash)
                        .map_err(|_| custom_error("Failed to verify password"))?;

                    //3. If password matches, generate JWT token and return it
                    if password_matches {
                        let claims = Claims{
                            sub: stored_user.uid.to_string(),
                            exp: 10000000000,
                        };
                        let token = generate_token(claims)
                            .map_err(|_| custom_error("Failed to generate token"))?;
                        return Ok(warp::reply::json(&token));
                    }
                    //4. If password doesn't match, return error
                    else {
                        return Ok(warp::reply::json(&"Invalid email or password"));
                    }
                },
                Err(_) => {
                    return Ok(warp::reply::json(&"Failed to parse user data"));
                },
            }
        },


        Ok(None) => Ok(warp::reply::json(&"Invalid email or password")),
        
        Err(_) => Ok(warp::reply::json(&"Failed to query the database")),
        }
    }


// async fn create_event_handler(event: Event, collections: Collections) -> Result<impl warp::Reply, warp::Rejection> {
// }

fn generate_token(claims: Claims) -> JWTResult<String> {
    let key = "secret".as_ref(); // Replace with your actual secret key
    encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(key))
}

//Helper function to pass the database to the handlers, since warp doesn't support passing state to handlers.
fn with_db(collections: Collections) -> impl Filter<Extract = (Collections,), Error = std::convert::Infallible> + Clone{
    warp::any().map(move || collections.clone())
}