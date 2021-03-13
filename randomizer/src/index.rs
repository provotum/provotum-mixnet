use actix_web::{get, HttpRequest, HttpResponse, Responder};

#[get("/")]
pub async fn get_index(_req: HttpRequest) -> impl Responder {
    HttpResponse::Ok().body("hi there!")
}

#[cfg(test)]
mod tests {
    use super::get_index;
    use actix_web::{http::StatusCode, test, App};

    #[actix_rt::test]
    async fn test_get_index_get() {
        let app = App::new().service(get_index);
        let mut test_app = test::init_service(app).await;
        let req = test::TestRequest::with_header("content-type", "text/plain").to_request();
        let resp = test::call_service(&mut test_app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let req = test::TestRequest::with_header("content-type", "text/plain").to_request();
        let resp = test::read_response(&mut test_app, req).await;
        assert_eq!(resp, "hi there!");
    }

    #[actix_rt::test]
    async fn test_get_index_post() {
        let app = App::new().service(get_index);
        let mut test_app = test::init_service(app).await;
        let req = test::TestRequest::post().uri("/").to_request();
        let resp = test::call_service(&mut test_app, req).await;
        assert!(resp.status().is_client_error());
    }
}
