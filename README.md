


```bash
cp .env.example .env
```

1. Put your 2captcha key in `TWOCAPTCHA_API_KEY`. Set `CAPTCHA_STRATEGY=auto` to solve reCAPTCHA v2 with 2captcha, or `manual` to solve it in a browser window.

2. also specify the link of the target web page: https://linkreclamatiogrwc.uk/

3. and site key: 6LfiehouAAAAAFr7759Kztp8FRrwjs0BRxuMZP28

4. run 
```bash
docker compose up --build
```

5. Open http://localhost:8080. The API is at http://localhost:8000.