-- ============================================================================
-- ZAHA AI Virtual Try-On - MySQL Schema
-- Database: u334425891_style_nova
--
-- How to import:
-- 1. phpMyAdmin: open https://auth-db1274.hstgr.io/index.php?db=u334425891_style_nova
--    Select database u334425891_style_nova, go to SQL tab, paste this file and Run.
-- 2. Command line: mysql -h auth-db1274.hstgr.io -u u334425891_style_nova -p u334425891_style_nova < database/schema.sql
--
-- Then set in your .env: DB_HOST, DB_USER, DB_PASSWORD, DB_NAME (see .env.example).
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Users: login and role (user = normal, superadmin = see all + delete any)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `users` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(64) NOT NULL,
  `password_hash` VARCHAR(255) NOT NULL,
  `role` ENUM('user', 'superadmin') NOT NULL DEFAULT 'user',
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Try-On History: each generation tied to a user
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `try_on_history` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` INT UNSIGNED NOT NULL,
  `generation_id` BIGINT UNSIGNED NOT NULL,
  `person_filename` VARCHAR(255) NOT NULL,
  `product_filename` VARCHAR(255) NOT NULL,
  `result_filenames` JSON NOT NULL COMMENT 'Array of output filenames e.g. ["result-123.png"]',
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_created_at` (`created_at`),
  CONSTRAINT `fk_try_on_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Optional: Insert a superadmin (password set by app on first run if none)
-- To set password manually, run in Node: require('bcrypt').hashSync('YourPassword', 10)
-- Then: UPDATE users SET password_hash = '<hash>' WHERE username = 'superadmin';
-- ----------------------------------------------------------------------------
-- INSERT INTO `users` (`username`, `password_hash`, `role`) VALUES
-- ('superadmin', '$2b$10$YourBcryptHashHere', 'superadmin');
