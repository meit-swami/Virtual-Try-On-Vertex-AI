-- ============================================================================
-- Migration: username -> email
-- Run this only if you already have the old schema with 'username' column.
-- If this is a fresh install, use schema.sql instead.
-- ============================================================================

-- Add email column
ALTER TABLE `users` ADD COLUMN `email` VARCHAR(255) NULL AFTER `id`;

-- Migrate existing data (username becomes email if it contains @, else user@migrated.local)
UPDATE `users` SET `email` = CASE
  WHEN `username` LIKE '%@%' THEN `username`
  WHEN `username` = 'superadmin' THEN 'superadmin@zaha.ai'
  ELSE CONCAT(`username`, '@user.local')
END WHERE `email` IS NULL;

-- Make email NOT NULL and unique
ALTER TABLE `users` MODIFY `email` VARCHAR(255) NOT NULL;
ALTER TABLE `users` ADD UNIQUE KEY `uk_email` (`email`);

-- Remove username
ALTER TABLE `users` DROP COLUMN `username`;
-- If you get "Can't DROP" due to old index, run: ALTER TABLE users DROP INDEX uk_username; first
