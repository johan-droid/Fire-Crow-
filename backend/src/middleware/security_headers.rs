use axum::http::header;
use axum::response::Response;

pub fn add_security_headers(mut response: Response) -> Response {
    response.headers_mut().insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    response.headers_mut().insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    response.headers_mut().insert(header::STRICT_TRANSPORT_SECURITY, "max-age=31536000; includeSubDomains; preload".parse().unwrap());
    response.headers_mut().insert("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()".parse().unwrap());
    response.headers_mut().insert(header::REFERRER_POLICY, "strict-origin-when-cross-origin".parse().unwrap());
    response
}
