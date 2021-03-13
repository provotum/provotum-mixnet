use actix_web::{get, HttpRequest, HttpResponse, Responder};

#[get("/health")]
pub async fn get_health(_req: HttpRequest) -> impl Responder {
    HttpResponse::NoContent()
}

#[cfg(test)]
mod tests {
    use super::get_health;
    use actix_web::{http::StatusCode, test, App};

    #[actix_rt::test]
    async fn test_get_health_get() {
        let app = App::new().service(get_health);
        let mut test_app = test::init_service(app).await;
        let req = test::TestRequest::with_header("content-type", "text/plain")
            .uri("/health")
            .to_request();
        let resp = test::call_service(&mut test_app, req).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[actix_rt::test]
    async fn test_get_health_post() {
        let app = App::new().service(get_health);
        let mut test_app = test::init_service(app).await;
        let req = test::TestRequest::post().uri("/health").to_request();
        let resp = test::call_service(&mut test_app, req).await;
        assert!(resp.status().is_client_error());
    }
}
