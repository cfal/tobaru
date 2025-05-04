use super::header_map::HeaderMap;
use super::http_parser::ParsedHttpData;

pub fn create_message(data: &ParsedHttpData) -> String {
    let mut msg = String::with_capacity(4096);
    msg.push_str(data.first_line());
    msg.push_str("\r\n");
    data.headers().append_headers_to_string(&mut msg);
    msg.push_str("\r\n");
    msg
}

pub fn update_base_path(request_path: &str, base_path: &str, new_base_path: &str) -> String {
    // if the request path is the base path, just return the new base path.
    // it's possible that base path has a trailing slash (eg /a/), while the request path is
    // /a, so check with starts_with.
    if base_path.starts_with(request_path) {
        if request_path.ends_with("/") && !new_base_path.ends_with("/") {
            let mut new_path = String::with_capacity(new_base_path.len() + 1);
            new_path.push_str(new_base_path);
            new_path.push('/');
            new_path
        } else {
            new_base_path.to_string()
        }
    } else {
        // if base path does not start with request_path, request_path must be longer.
        let sub_path = &request_path[base_path.len()..];

        let end_slash = new_base_path.ends_with("/");
        let start_slash = sub_path.starts_with("/");

        if end_slash && start_slash {
            let mut new_path = String::with_capacity(new_base_path.len() + sub_path.len() - 1);
            new_path.push_str(new_base_path);
            new_path.push_str(&sub_path[1..]);
            new_path
        } else if !end_slash && !start_slash {
            let mut new_path = String::with_capacity(new_base_path.len() + sub_path.len() + 1);
            new_path.push_str(new_base_path);
            new_path.push('/');
            new_path.push_str(sub_path);
            new_path
        } else {
            let mut new_path = String::with_capacity(new_base_path.len() + sub_path.len());
            new_path.push_str(new_base_path);
            new_path.push_str(sub_path);
            new_path
        }
    }
}

#[test]
pub fn test_update_base_path_request_matches_base() {
    assert!(update_base_path("/a", "/a/", "/abc") == "/abc");
    assert!(update_base_path("/a/", "/a", "/abc") == "/abc/");
    assert!(update_base_path("/a/", "/a/", "/abc") == "/abc/");
    assert!(update_base_path("/a/", "/a", "/") == "/");
    assert!(update_base_path("/a/", "/a/", "/") == "/");
    assert!(update_base_path("/a", "/a/", "/") == "/");
}

#[test]
pub fn test_update_base_path_sub_file() {
    assert!(update_base_path("/a/b/index.html", "/a", "/abc") == "/abc/b/index.html");
    assert!(update_base_path("/a/b/index.html", "/a", "/") == "/b/index.html");
    assert!(update_base_path("/a/index.html", "/a", "/") == "/index.html");
    assert!(update_base_path("/a/b/index.html", "/a/", "/abc") == "/abc/b/index.html");
    assert!(update_base_path("/a/b/index.html", "/a/", "/") == "/b/index.html");
    assert!(update_base_path("/a/index.html", "/a/", "/") == "/index.html");
}

#[test]
pub fn test_update_base_path_sub_dir() {
    assert!(update_base_path("/a/b/", "/a", "/abc") == "/abc/b/");
    assert!(update_base_path("/a/b", "/a", "/abc") == "/abc/b");
    assert!(update_base_path("/a/b/", "/a/", "/abc") == "/abc/b/");
    assert!(update_base_path("/a/b", "/a/", "/abc") == "/abc/b");
    assert!(update_base_path("/a/b", "/a", "/") == "/b");
    assert!(update_base_path("/a/b/", "/a", "/") == "/b/");
}
