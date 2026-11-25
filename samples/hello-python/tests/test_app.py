from hello.app import app, greeting


def test_greets_the_world_by_default():
    assert greeting(None) == "Hello, world!"
    assert greeting("  ") == "Hello, world!"


def test_hello_answers_with_json():
    response = app.test_client().get("/hello?name=Talos")
    assert response.status_code == 200
    assert response.get_json() == {"message": "Hello, Talos!"}


def test_health_says_ok():
    assert app.test_client().get("/health").get_json() == {"status": "ok"}
