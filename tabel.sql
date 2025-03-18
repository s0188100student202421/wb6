-- Создание базы данных
CREATE DATABASE u68824;
USE u68824;

-- Таблица пользователей
CREATE TABLE users (
    user_id INT NOT NULL AUTO_INCREMENT,
    login VARCHAR(255),
    hashed_password VARCHAR(255),
    PRIMARY KEY (user_id)
);

-- Таблица языков программирования
CREATE TABLE programming_languages (
    id INT NOT NULL AUTO_INCREMENT,
    guid VARCHAR(255),
    PRIMARY KEY (id)
);

-- Таблица заявок (applications)
CREATE TABLE applications (
    id INT NOT NULL AUTO_INCREMENT,
    full_name VARCHAR(150) NOT NULL,
    gender VARCHAR(10) NOT NULL,
    phone VARCHAR(15) NOT NULL,
    email VARCHAR(100) NOT NULL,
    date DATE NOT NULL,
    bio TEXT NOT NULL,
    agreement TINYINT(1) NOT NULL,
    user_id INT,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Таблица связки заявок и языков программирования
CREATE TABLE application_languages (
    application_id INT NOT NULL,
    language_id INT NOT NULL,
    PRIMARY KEY (application_id, language_id),
    FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE CASCADE,
    FOREIGN KEY (language_id) REFERENCES programming_languages(id) ON DELETE CASCADE
);

