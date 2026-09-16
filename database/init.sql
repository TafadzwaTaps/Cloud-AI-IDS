CREATE DATABASE CloudAI_IDS;
GO

USE CloudAI_IDS;
GO

CREATE TABLE intrusion_logs (
    id INT IDENTITY(1,1) PRIMARY KEY,
    total_records INT NOT NULL,
    attacks_detected INT NOT NULL,
    benign_detected INT NOT NULL,
    attack_ratio FLOAT NOT NULL,
    detected_at DATETIME DEFAULT GETDATE()
);
GO
