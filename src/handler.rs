use crate::model::{UserModel, UserModelResponse};

//pub struct UserModelResponse {
//    pub id: Option<i32>, //Int primary key auto_increment not null
//    pub name: Option<String>, //Varchar(20)
//    pub email: Option<String>, //VarChar(40) unique
//    pub password_hash: Option<String>, //VarChar(255)
//    pub session_id: Option<String>,
//}

pub fn filter_db_record(record: &UserModel) -> UserModelResponse {
    UserModelResponse {
        id: Some(record.id),
        name: Some(record.name.clone()),
        email: Some(record.email.clone()),
        password_hash: Some(record.password_hash.clone()),
        session_id: Some(record.session_id.clone()),
    }
}