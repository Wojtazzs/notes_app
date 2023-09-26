use std::ops::Deref;
use std::sync::{Arc, Mutex};

use sqlx::{MySql, Pool};

use env_logger;

use actix_web::cookie::Key;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
//use actix_web::middleware::Logger;

use actix_files as fs;

use actix_session::config::PersistentSession;
use actix_session::storage::CookieSessionStore;
use actix_session::{Session, SessionMiddleware};

use openssl::ssl::{SslAcceptor, SslFiletype};

use password_auth::{generate_hash, verify_password};

use model::{
    LoginModel, NoteModelCreate, NoteModelSave, UserModel, UserModelCreate, UserModelPost,
    UserModelResponse,
};
mod model;

mod auth;
mod handler;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::Pool<sqlx::MySql>,
    pub session_store: Arc<Mutex<Vec<SessionDetails>>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct SessionDetails {
    session_id: String,
    name: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut builder = SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls()).unwrap();

    builder
        .set_private_key_file("ssl.key", SslFiletype::PEM)
        .unwrap();
    builder
        .set_certificate_chain_file("certificate.pem")
        .unwrap();

    dotenv::dotenv().ok();
    let ip = std::env::var("IP").expect("IP must be set");

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_pool = sqlx::MySqlPool::connect(&database_url).await.unwrap();
    let sessionstore = load_sessions(db_pool.clone()).await.unwrap();

    let app_state = AppState {
        db: db_pool.clone(),
        session_store: Arc::clone(&sessionstore),
    };

    let secret_key = Key::try_generate();

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            //.wrap(Logger::new("\n %T %s %r \n"))
            .service(fs::Files::new("/static", "./public").show_files_listing())
            .service(index)
            .service(login)
            .service(register)
            .service(login_user)
            .service(new_user)
            .service(email_check)
            .service(start)
            .service(name_check)
            .service(note_save)
            .service(note_load)
            .service(note_create)
            .service(tos)
            .service(logout)
            .wrap(
                SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    secret_key.clone().unwrap(),
                )
                .cookie_secure(false)
                .session_lifecycle(PersistentSession::default().session_ttl_extension_policy(
                    actix_session::config::TtlExtensionPolicy::OnEveryRequest,
                ))
                .build(),
            )
            .default_service(web::route().to(|| HttpResponse::NotFound()))
    })
    //.bind_openssl(format!("{}:8080", ip), builder)?
    .bind((ip, 8081))?
    .run()
    .await
}

async fn load_sessions(db: Pool<MySql>) -> Result<Arc<Mutex<Vec<SessionDetails>>>, sqlx::Error> {
    let result = sqlx::query_as!(SessionDetails, r#"SELECT session_id, name FROM users"#)
        .fetch_one(&db)
        .await
        .unwrap();

    Ok(Arc::new(Mutex::new(vec![result])))
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body(include_str!("../public/html/index.html"))
}

#[post("/start")]
async fn start(data: web::Data<AppState>, session_responder: Session) -> impl Responder {
    let user_sessions = session_responder.get::<String>("session_id").unwrap();
    if user_sessions.is_none() {
        return HttpResponse::Ok().body(include_str!("../public/html/login.html"));
    }
    for session in data.session_store.lock().unwrap().iter() {
        if session.session_id == user_sessions.clone().unwrap() {
            let result = sqlx::query_as!(
                NoteModelCreate,
                r#"SELECT note_title, note_body, user_name FROM notes where user_name = ?"#,
                session.name.clone(),
            )
            .fetch_one(&data.db)
            .await
            .unwrap();

            let menu_body = menu_builder(session.name.clone(), result.note_body);
            return HttpResponse::Ok().body(menu_body);
        }
    }

    HttpResponse::Ok().body(include_str!("../public/html/login.html"))
}

#[post("/note/save")]
async fn note_save(
    data: web::Data<AppState>,
    note: web::Form<NoteModelSave>,
    session: Session,
) -> impl Responder {
    let username = get_username(&data, session);

    let _save = sqlx::query!(
        r#"
        UPDATE notes
        SET note_body = ?
        WHERE user_name = ?
        "#,
        note.main,
        username
    )
    .execute(&data.db)
    .await
    .expect("Error");

    HttpResponse::Ok()
}

#[post("/note/load")]
async fn note_load(data: web::Data<AppState>, session: Session) -> impl Responder {
    let username = get_username(&data, session);

    let body = sqlx::query!(
        r#"
    SELECT note_body
    FROM notes
    WHERE user_name = ?
    "#,
        username
    )
    .fetch_one(&data.db)
    .await
    .expect("Error");

    HttpResponse::Ok().body(body.note_body.unwrap())
}

#[post("/note/create")]
async fn note_create(
    data: web::Data<AppState>,
    note: web::Form<NoteModelCreate>,
    session: Session,
) -> impl Responder {
    let name = get_username(&data, session);
    let _result = sqlx::query(
        r#"INSERT INTO notes 
    (note_id, note_title, note_body, updated_date, user_name)
    VALUES
    (null, ?, "", null, ?)
    "#,
    )
    .bind(note.note_title.clone())
    .bind(name)
    .execute(&data.db)
    .await
    .unwrap();

    HttpResponse::Ok().body("")
}

#[get("/login")]
async fn login() -> impl Responder {
    let login_form = include_str!("../public/html/login.html");
    HttpResponse::Ok().body(login_form)
}

#[get("/login/logout")]
async fn logout(session: Session) -> impl Responder {
    session.remove("session_id").unwrap();
    let login_form = include_str!("../public/html/login.html");
    HttpResponse::Ok().body(login_form)
}

#[get("/register")]
async fn register() -> impl Responder {
    let register_form = include_str!("../public/html/register.html");
    HttpResponse::Ok().body(register_form)
}

#[get("/register/tos")]
async fn tos() -> impl Responder {
    HttpResponse::Ok().body(include_str!("../public/html/tos.html"))
}

#[post("/login/user")]
pub async fn login_user(
    data: web::Data<AppState>,
    login_info: web::Form<LoginModel>,
    session: Session,
) -> impl Responder {
    if (login_info.name.as_ref().unwrap().len() < 4)
        | (login_info.name.as_ref().unwrap().len() > 32)
        | !valid_characters(login_info.name.as_ref().unwrap(), false)
        | !valid_characters(login_info.password.as_ref().unwrap(), false)
    {
        let mut response: String = include_str!("../public/html/login.html").to_string();
        response = format!(
            "{} <script>alert('Wrong username or password!');</script>",
            response
        );
        return HttpResponse::Ok().body(response);
    }

    let result = sqlx::query_as!(
        UserModel,
        r#"SELECT * FROM users where name = ?"#,
        login_info.name,
    )
    .fetch_all(&data.db)
    .await
    .unwrap();

    if result.len() == 0 {
        let mut response: String = include_str!("../public/html/login.html").to_string();
        response = format!(
            "{} <script>alert('Wrong username or password!');</script>",
            response
        );
        return HttpResponse::Ok().body(response);
    }
    for user in result {
        if verify_password(&login_info.password.as_ref().unwrap(), &user.password_hash).is_err() {
            continue;
        } else {
            session
                .insert("session_id", user.session_id.clone())
                .unwrap();
            data.session_store.lock().unwrap().push(SessionDetails {
                session_id: user.session_id.clone(),
                name: user.name.clone(),
            });

            let result = sqlx::query_as!(
                NoteModelCreate,
                r#"SELECT note_title, note_body, user_name FROM notes where user_name = ?"#,
                user.name.clone(),
            )
            .fetch_one(&data.db)
            .await
            .unwrap();

            let menu_body = menu_builder(user.name, result.note_body);
            return HttpResponse::Ok().body(menu_body);
        }
    }
    let mut response: String = include_str!("../public/html/login.html").to_string();
    response = format!(
        "{} <script>alert('Wrong username or password!');</script>",
        response
    );
    HttpResponse::Ok().body(response)
}

fn menu_builder(username: String, note_body: Option<String>) -> String {
    let menu_body = format!(
        "<div class='left-side-menu vlg' id='left-main'><ul class='logout' hx-get='/login/logout' hx-trigger='click' hx-target='#user-interface' hx-swap='innerHTML'>Logout</ul><ul class='user'>{}</ul><ul id='save'></ul><ul></ul></div>",
        username
    );

    let js_script = r#"
        <script>
            
            var textareas = document.getElementsByTagName('textarea');
            var count = textareas.length;
            for(var i=0;i<count;i++){
                textareas[i].onkeydown = function(e){
                    if(e.keyCode==9 || e.which==9){
                        e.preventDefault();
                        var s = this.selectionStart;
                        this.value = this.value.substring(0,this.selectionStart) + '\t' + this.value.substring(this.selectionEnd);
                        this.selectionEnd = s+1; 
                    }
                    if (e.keyCode === 83 && (navigator.platform.match(`Mac`) ? e.metaKey : e.ctrlKey)) {
                        e.preventDefault();
                    }
                }
            }
            </script>"#
        .to_string();

    let text_body = format!("{}<div class='right-side-text vlg'><textarea class='dgray' hx-post='/note/save' hx-target='#save' name='main' hx-trigger='keyup changed delay:600ms, keydown[ctrlKey&&key==`s`], keydown[metaKey&&key==`s`]'>{}</textarea></div>",
        js_script,
        note_body.unwrap()
    );

    return format!("{}{}", menu_body, text_body);
}

#[post("/email_check")]
async fn email_check(data: web::Data<AppState>, post: web::Form<UserModelPost>) -> impl Responder {
    let email = post.email.as_ref().expect("Error");
    if !valid_email(email) {
        return HttpResponse::Ok()
            .body("<p class='server-text error-text' >Please enter valid email address</p>");
    }

    if email_taken(email, data.clone()).await {
        return HttpResponse::Ok()
            .body("<p class='server-text error-text' >Email is already taken</p>");
    }

    return HttpResponse::Ok().body("<p class='server-text success-text'>Email is aviable</p>");
}

#[post("/name_check")]
async fn name_check(data: web::Data<AppState>, post: web::Form<UserModelPost>) -> impl Responder {
    let name = post.name.as_ref().expect("Error");

    if name_taken(name, data.clone()).await {
        return HttpResponse::Ok()
            .body("<p class='server-text error-text' >Username is already taken</p>");
    }

    return HttpResponse::Ok().body("<p class='server-text success-text'>Username is aviable</p>");
}

async fn email_taken(email: &str, data: web::Data<AppState>) -> bool {
    let users: Vec<UserModel> =
        sqlx::query_as!(UserModel, r#"SELECT * FROM users where email = ?"#, email)
            .fetch_all(&data.db)
            .await
            .unwrap();

    let users_responses = users
        .into_iter()
        .map(|user| handler::filter_db_record(&user))
        .collect::<Vec<UserModelResponse>>();

    if users_responses.len() == 0 {
        return false;
    }
    return true;
}

async fn name_taken(name: &str, data: web::Data<AppState>) -> bool {
    let users: Vec<UserModel> =
        sqlx::query_as!(UserModel, r#"SELECT * FROM users where name = ?"#, name)
            .fetch_all(&data.db)
            .await
            .unwrap();

    let users_responses = users
        .into_iter()
        .map(|user| handler::filter_db_record(&user))
        .collect::<Vec<UserModelResponse>>();

    if users_responses.len() == 0 {
        return false;
    }
    return true;
}

fn valid_password(password: &str) -> bool {
    if (password.len() < 4) | (password.len() > 255) {
        return false;
    }

    true
}

fn valid_username(username: &str) -> bool {
    if (username.len() < 4) | (username.len() > 32) {
        return false;
    }

    true
}

fn valid_email(email: &str) -> bool {
    if (email.len() < 5) | (email.len() > 48) | !email.contains("@") | !email.contains(".") {
        return false;
    }

    true
}

fn valid_characters(string: &str, is_mail: bool) -> bool {
    let valid_chars = vec![
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
        's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
        'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1',
        '2', '3', '4', '5', '6', '7', '8', '9', '-', '_',
    ];

    let valid_chars_mail = vec!['@', '.'];

    for char in string.chars() {
        if !valid_chars.contains(&char) {
            if is_mail {
                if !valid_chars_mail.contains(&char) {
                    return false;
                }
            } else {
                return false;
            }
        }
    }

    true
}

#[post("/new_user")]
async fn new_user(data: web::Data<AppState>, post: web::Form<UserModelPost>) -> impl Responder {
    let mut response = String::new();

    if !valid_password(post.password.as_ref().expect("Error")) {
        response.push_str(
            "<p class='server-text error-text' >Password must be longer than 4 characters</p>",
        );
    }
    if !valid_email(post.email.as_ref().expect("Error")) {
        response
            .push_str("<p class='server-text error-text' >Please enter valid email address</p>");
    }
    if email_taken(post.email.as_ref().expect("Error"), data.clone()).await {
        response.push_str("<p class='server-text error-text' >Email is already taken</p>");
    }
    if !valid_username(post.name.as_ref().expect("Error")) {
        response.push_str(
            "<p class='server-text error-text' >Username should be between 4 and 20 characters</p>",
        );
    }
    if !valid_characters(post.name.as_ref().expect("Error"), false)
        | !valid_characters(post.email.as_ref().expect("Error"), true)
        | !valid_characters(post.password.as_ref().expect("Error"), false)
    {
        response.push_str("<p class='server-text error-text' >Used invalid characters</p>");
    }
    if post.policy.as_ref().is_none() {
        response.push_str("<p class='server-text error-text' >Please accept the policy</p>");
    }

    if response.len() > 0 {
        return HttpResponse::Ok().body(response);
    }

    let password = post.password.as_ref().expect("Error");
    let password_hash = generate_hash(password);
    let mut session_id: String = auth::generate_session_token();
    while session_aviable(data.clone(), session_id.clone()).await {
        session_id = auth::generate_session_token();
    }

    let user = UserModelCreate {
        name: post.name.as_ref().expect("Error").to_string(),
        email: post.email.as_ref().expect("Error").to_string(),
        password_hash: password_hash,
        session_id: session_id.clone(),
    };

    let result = sqlx::query(
        r#"
        INSERT INTO users 
        (id, name, email, password_hash, session_id)
        VALUES 
        (Null, ?, ?, ?, ?)
        "#,
    )
    .bind(user.name.clone())
    .bind(user.email.clone())
    .bind(user.password_hash)
    .bind(user.session_id)
    .execute(&data.db)
    .await
    .expect("Error");

    data.session_store.lock().unwrap().push(SessionDetails {
        session_id: session_id.clone(),
        name: user.name.clone(),
    });

    if result.rows_affected() == 0 {
        return HttpResponse::Ok().body("<p class='server-text error-text' >Database error</p>");
    }

    return HttpResponse::Ok().body("<p class='server-text success-text' >User created</p>");
}

async fn session_aviable(data: web::Data<AppState>, session: String) -> bool {
    let users: Vec<UserModel> = sqlx::query_as!(
        UserModel,
        r#"SELECT * FROM users where session_id = ?"#,
        session
    )
    .fetch_all(&data.db)
    .await
    .unwrap();

    if users.len() == 0 {
        return false;
    }
    return true;
}

fn get_username(data: &AppState, session: Session) -> String {
    let user_sessions = session.get::<String>("session_id").unwrap();
    if user_sessions.is_none() {
        return "%error%".to_string();
    }
    for session in data.session_store.lock().unwrap().iter() {
        if session.session_id == user_sessions.clone().unwrap() {
            return session.name.deref().to_string();
        }
    }
    return "%error%".to_string();
}
