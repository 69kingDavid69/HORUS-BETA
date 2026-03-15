-- ============================================================
-- HORUS — Schema MySQL
-- Orden de creación: de tablas independientes a dependientes
-- Todas las restricciones (UNIQUE, INDEX, FK) dentro del CREATE TABLE
-- ============================================================

-- 1. USUARIOS: No depende de nadie, es la base de todo
CREATE TABLE Users (
    id            INT NOT NULL AUTO_INCREMENT,
    email         VARCHAR(255) NOT NULL,
    username      VARCHAR(255) NULL,
    full_name     VARCHAR(255) NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active     BOOLEAN NOT NULL DEFAULT 1,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login    TIMESTAMP NULL,

    PRIMARY KEY (id),
    UNIQUE KEY users_email_unique (email),
    UNIQUE KEY users_username_unique (username)
);

-- 2. PERFILES DE USUARIO: Depende de Users
CREATE TABLE UserProfiles (
    user_id          INT NOT NULL,
    nombre_completo  VARCHAR(255) NOT NULL,
    cedula           VARCHAR(50) NOT NULL,
    telefono         VARCHAR(50) NULL,
    pais             VARCHAR(100) NULL,
    ciudad           VARCHAR(100) NULL,
    updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (user_id),
    UNIQUE KEY userprofiles_cedula_unique (cedula),
    CONSTRAINT userprofiles_user_id_foreign
        FOREIGN KEY (user_id) REFERENCES Users(id)
);

-- 3. ROLES: No depende de nadie
CREATE TABLE Roles (
    id          INT NOT NULL AUTO_INCREMENT,
    name        VARCHAR(50) NOT NULL,
    description VARCHAR(255) NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY roles_name_unique (name)
);

-- 4. ASIGNACIÓN DE ROLES A USUARIOS: Depende de Users y Roles
CREATE TABLE UserRoles (
    user_id     INT NOT NULL,
    role_id     INT NOT NULL,
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (user_id, role_id),
    CONSTRAINT userroles_user_id_foreign
        FOREIGN KEY (user_id) REFERENCES Users(id),
    CONSTRAINT userroles_role_id_foreign
        FOREIGN KEY (role_id) REFERENCES Roles(id)
);

-- 5. SIMULACIONES (escaneos de red): Depende de Users
CREATE TABLE Simulations (
    id                INT NOT NULL AUTO_INCREMENT,
    user_id           INT NOT NULL,
    scan_type         ENUM('network_detect', 'discover', 'deep_scan') NOT NULL,
    target_subnet     VARCHAR(50) NULL,
    target_ip         VARCHAR(45) NULL,
    status            ENUM('pending', 'running', 'completed', 'failed') NOT NULL DEFAULT 'pending',
    start_time        TIMESTAMP NULL,
    end_time          TIMESTAMP NULL,
    scan_time_seconds INT NULL,
    nmap_version      VARCHAR(50) NULL,
    nmap_command      TEXT NULL,
    error_message     TEXT NULL,
    json_response     LONGTEXT NULL,
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    INDEX simulations_user_id_created_at_index (user_id, created_at),
    INDEX simulations_target_ip_index (target_ip),
    INDEX simulations_status_index (status),
    CONSTRAINT simulations_user_id_foreign
        FOREIGN KEY (user_id) REFERENCES Users(id)
);

-- 6. HOSTS (dispositivos descubiertos): Depende de Simulations y Users
CREATE TABLE Hosts (
    id              INT NOT NULL AUTO_INCREMENT,
    simulation_id   INT NOT NULL,
    user_id         INT NOT NULL,
    ip_address      VARCHAR(45) NOT NULL,
    mac_address     VARCHAR(17) NULL,
    mac_vendor      VARCHAR(255) NULL,
    hostname        VARCHAR(255) NULL,
    os_detection    VARCHAR(255) NULL,
    device_type     VARCHAR(100) NULL,
    discovered_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_scanned_at TIMESTAMP NULL,

    PRIMARY KEY (id),
    INDEX hosts_user_id_ip_address_index (user_id, ip_address),
    INDEX hosts_simulation_id_index (simulation_id),
    INDEX hosts_ip_address_index (ip_address),
    CONSTRAINT hosts_simulation_id_foreign
        FOREIGN KEY (simulation_id) REFERENCES Simulations(id),
    CONSTRAINT hosts_user_id_foreign
        FOREIGN KEY (user_id) REFERENCES Users(id)
);

-- 7. PUERTOS detectados en cada host: Depende de Hosts
CREATE TABLE Ports (
    id            INT NOT NULL AUTO_INCREMENT,
    host_id       INT NOT NULL,
    port_number   INT NOT NULL,
    protocol      ENUM('tcp', 'udp') NOT NULL DEFAULT 'tcp',
    state         VARCHAR(50) NOT NULL,
    service       VARCHAR(100) NULL,
    product       VARCHAR(255) NULL,
    version       VARCHAR(100) NULL,
    cpe           VARCHAR(255) NULL,
    extra_info    TEXT NULL,
    discovered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    INDEX ports_port_number_service_index (port_number, service),
    INDEX ports_host_id_index (host_id),
    CONSTRAINT ports_host_id_foreign
        FOREIGN KEY (host_id) REFERENCES Hosts(id)
);

-- 8. VULNERABILIDADES encontradas: Depende de Simulations, Hosts y Ports
CREATE TABLE Vulnerabilities (
    id            INT NOT NULL AUTO_INCREMENT,
    simulation_id INT NOT NULL,
    host_id       INT NOT NULL,
    port_id       INT NULL,
    script_id     VARCHAR(255) NOT NULL,
    severity      ENUM('critical', 'high', 'medium', 'low') NOT NULL,
    output        LONGTEXT NULL,
    detected_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    INDEX vulnerabilities_simulation_id_index (simulation_id),
    INDEX vulnerabilities_host_id_index (host_id),
    INDEX vulnerabilities_severity_index (severity),
    CONSTRAINT vulnerabilities_simulation_id_foreign
        FOREIGN KEY (simulation_id) REFERENCES Simulations(id),
    CONSTRAINT vulnerabilities_host_id_foreign
        FOREIGN KEY (host_id) REFERENCES Hosts(id),
    CONSTRAINT vulnerabilities_port_id_foreign
        FOREIGN KEY (port_id) REFERENCES Ports(id)
);

-- 9. PRUEBAS DE CREDENCIALES (Hydra): Depende de Simulations, Hosts, Ports y Users
CREATE TABLE CredentialTests (
    id             INT NOT NULL AUTO_INCREMENT,
    simulation_id  INT NOT NULL,
    host_id        INT NOT NULL,
    port_id        INT NOT NULL,
    user_id        INT NOT NULL,
    service        VARCHAR(100) NOT NULL,
    status         VARCHAR(100) NOT NULL,
    found_username VARCHAR(255) NULL,
    found_password INT NULL,
    risk_score     TINYINT NULL,
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    INDEX credentialtests_simulation_id_index (simulation_id),
    INDEX credentialtests_user_id_index (user_id),
    INDEX credentialtests_service_index (service),
    CONSTRAINT credentialtests_simulation_id_foreign
        FOREIGN KEY (simulation_id) REFERENCES Simulations(id),
    CONSTRAINT credentialtests_host_id_foreign
        FOREIGN KEY (host_id) REFERENCES Hosts(id),
    CONSTRAINT credentialtests_port_id_foreign
        FOREIGN KEY (port_id) REFERENCES Ports(id),
    CONSTRAINT credentialtests_user_id_foreign
        FOREIGN KEY (user_id) REFERENCES Users(id)
);

-- 10. REPORTES PDF generados: Depende de Simulations y Users
CREATE TABLE Reports (
    id            INT NOT NULL AUTO_INCREMENT,
    simulation_id INT NOT NULL,
    user_id       INT NOT NULL,
    filename      VARCHAR(255) NOT NULL,
    path          VARCHAR(1024) NOT NULL,
    size_bytes    BIGINT NULL,
    version       INT NOT NULL DEFAULT 1,
    generated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    INDEX reports_simulation_id_index (simulation_id),
    INDEX reports_user_id_index (user_id),
    CONSTRAINT reports_simulation_id_foreign
        FOREIGN KEY (simulation_id) REFERENCES Simulations(id),
    CONSTRAINT reports_user_id_foreign
        FOREIGN KEY (user_id) REFERENCES Users(id)
);

-- 11. LOG DE AUDITORÍA: Depende de Users
CREATE TABLE AuditLog (
    id            INT NOT NULL AUTO_INCREMENT,
    user_id       INT NOT NULL,
    action        VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NULL,
    resource_id   INT NULL,
    ip_address    VARCHAR(45) NULL,
    user_agent    VARCHAR(512) NULL,
    details       JSON NULL,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    INDEX auditlog_user_id_created_at_index (user_id, created_at),
    INDEX auditlog_action_index (action),
    CONSTRAINT auditlog_user_id_foreign
        FOREIGN KEY (user_id) REFERENCES Users(id)
);

-- 12. RESULTADOS DE ANÁLISIS IA (opcional): Depende de Simulations
CREATE TABLE IF NOT EXISTS AIAnalysisResults (
    id                 INT NOT NULL AUTO_INCREMENT,
    simulation_id      INT NOT NULL,
    model_version      VARCHAR(100) NULL,
    risk_score_global  TINYINT NULL,
    severity_summary   JSON NULL,
    findings           LONGTEXT NULL,
    recommendations    LONGTEXT NULL,
    analyzed_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY ai_analysis_results_simulation_id_unique (simulation_id),
    CONSTRAINT ai_analysis_results_simulation_id_foreign
        FOREIGN KEY (simulation_id) REFERENCES Simulations(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);
