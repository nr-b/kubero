/*
  Warnings:

  - Made the column `providerId` on table `User` required. Existing NULL values will have a random value generated.

*/
-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "username" TEXT NOT NULL,
    "firstName" TEXT,
    "lastName" TEXT,
    "email" TEXT NOT NULL,
    "emailVerified" DATETIME,
    "password" TEXT NOT NULL,
    "twoFaSecret" TEXT,
    "twoFaEnabled" BOOLEAN NOT NULL DEFAULT false,
    "image" TEXT,
    "roleId" TEXT,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "lastLogin" DATETIME,
    "lastIp" TEXT,
    "provider" TEXT NOT NULL DEFAULT 'local',
    "providerId" TEXT NOT NULL,
    "providerData" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "User_roleId_fkey" FOREIGN KEY ("roleId") REFERENCES "Role" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);
INSERT INTO "new_User" ("createdAt", "email", "emailVerified", "firstName", "id", "image", "isActive", "lastIp", "lastLogin", "lastName", "password", "provider", "providerData", "providerId", "roleId", "twoFaEnabled", "twoFaSecret", "updatedAt", "username") SELECT "createdAt", "email", "emailVerified", "firstName", "id", "image", "isActive", "lastIp", "lastLogin", "lastName", "password", coalesce("provider", 'local') AS "provider", "providerData", coalesce("providerId", hex(randomblob(16))) AS "providerId", "roleId", "twoFaEnabled", "twoFaSecret", "updatedAt", "username" FROM "User";
DROP TABLE "User";
ALTER TABLE "new_User" RENAME TO "User";
CREATE UNIQUE INDEX "User_username_key" ON "User"("username");
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
CREATE UNIQUE INDEX "User_provider_providerId_key" ON "User"("provider", "providerId");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
