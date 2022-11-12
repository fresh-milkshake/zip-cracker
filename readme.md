
# Информация

Реализация брута зипы на основе кода [статьи](https://agourlay.github.io/brute-forcing-protected-zip-rust/) от автора [Arnaud Gourlay](https://github.com/agourlay).

## Особенность реалиазции

Для подбора пароля создаются потоки для проверки правильности пароля, и поток для прохода по файлу словаря. который на каждой итерации передает пароль в поток для проверки, из которого поток для проверки пароля берет пароль и проверяет его.

## Запуск

1. `git clone https://github.com/immacool/zip-cracker.git`
2. `cd zip-cracker`
3. `cargo run --release -- <zip_file> -d <dictionary>`
