use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow)]
#[allow(non_snake_case)]
pub struct UserModel {
    pub id: u64,               //Int primary key auto_increment not null
    pub name: String,          //Varchar(20)
    pub email: String,         //VarChar(40) unique
    pub password_hash: String, //VarChar(255)
    pub session_id: String,
}

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow)]
#[allow(non_snake_case)]
pub struct UserModelCreate {
    pub name: String,          //Varchar(20)
    pub email: String,         //VarChar(40) unique
    pub password_hash: String, //VarChar(255)
    pub session_id: String,
}

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow)]
#[allow(non_snake_case)]
pub struct UserModelResponse {
    pub id: Option<u64>,               //Int primary key auto_increment not null
    pub name: Option<String>,          //Varchar(20)
    pub email: Option<String>,         //VarChar(40) unique
    pub password_hash: Option<String>, //VarChar(255)
    pub session_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct UserModelPost {
    pub name: Option<String>,     //Varchar(20)
    pub email: Option<String>,    //VarChar(40) unique
    pub password: Option<String>, //VarChar(255)
    pub policy: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct LoginModel {
    pub name: Option<String>,     //Varchar(20)
    pub password: Option<String>, //VarChar(255)
}

#[derive(Deserialize, Serialize)]
pub struct NoteModel {
    pub note_id: u64,
    pub note_title: String,
    pub note_body: String,
    pub user_id: u64,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct NoteModelSave {
    pub main: String,
}

#[derive(Deserialize, Serialize)]
pub struct NoteModelCreate {
    pub note_title: Option<String>,
    pub note_body: Option<String>,
    pub user_name: String,
}
