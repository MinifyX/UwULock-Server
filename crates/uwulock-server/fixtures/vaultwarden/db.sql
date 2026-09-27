BEGIN TRANSACTION;
CREATE TABLE __diesel_schema_migrations (
       version VARCHAR(50) PRIMARY KEY NOT NULL,
       run_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE archives (
    user_uuid   CHAR(36) NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    cipher_uuid CHAR(36) NOT NULL REFERENCES ciphers (uuid) ON DELETE CASCADE,
    archived_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_uuid, cipher_uuid)
);
CREATE TABLE attachments (
  id          TEXT    NOT NULL PRIMARY KEY,
  cipher_uuid TEXT    NOT NULL REFERENCES ciphers (uuid),
  file_name   TEXT    NOT NULL,
  file_size   INTEGER NOT NULL

, akey TEXT);
INSERT INTO "attachments" VALUES('55a07c00f6d22b5cfb46','f5b8199f-7dd6-4368-8af6-3940d5838def','2.I44+UZihLdbaDoJvkIx8Cw==|vorY9A/JKXSlLroLjtdUiA==|Aq8rkseo2IQJTYJX87GFLzsqbxt2WRZjsqfHps5nOwQ=',81,'2.ft/3qgFX5sJbndS0FvF6dA==|QQWtXFnKFv7gT4da5fPYNmMhz4EpiBQhmKQleJP/4RpSwjx5VmWCx0K3ydyHX38LqExug+P4xffPaHoOFEuxcghQcWn9aX6XTmRMbzOHIV4=|SCEO177edAlxGF/b4sLT/SX/nKnsXIWf/xqsHUbEzVo=');
CREATE TABLE "auth_requests" (
    uuid                        TEXT NOT NULL PRIMARY KEY,
    user_uuid                   TEXT NOT NULL,
    organization_uuid           TEXT,
    request_device_identifier   TEXT NOT NULL,
    device_type                 INTEGER NOT NULL,
    request_ip                  TEXT NOT NULL,
    response_device_id          TEXT,
    access_code                 TEXT NOT NULL,
    public_key                  TEXT NOT NULL,
    enc_key                     TEXT,
    master_password_hash        TEXT,
    approved                    BOOLEAN,
    creation_date               DATETIME NOT NULL,
    response_date               DATETIME,
    authentication_date         DATETIME,
    FOREIGN KEY (user_uuid) REFERENCES users (uuid),
    FOREIGN KEY (organization_uuid) REFERENCES organizations (uuid)
);
CREATE TABLE "ciphers"(
  uuid              TEXT     NOT NULL PRIMARY KEY,
  created_at        DATETIME NOT NULL,
  updated_at        DATETIME NOT NULL,
  user_uuid         TEXT     REFERENCES users(uuid),
  organization_uuid TEXT     REFERENCES organizations(uuid),
  atype             INTEGER  NOT NULL,
  name              TEXT     NOT NULL,
  notes             TEXT,
  fields            TEXT,
  data              TEXT     NOT NULL,
  password_history  TEXT,
  deleted_at        DATETIME
, reprompt INTEGER, "key" TEXT);
INSERT INTO "ciphers" VALUES('f5b8199f-7dd6-4368-8af6-3940d5838def','2026-09-27 21:34:49.514361604','2026-09-27 21:34:49.514801686','abd15dba-ed03-46ca-83e6-af5cda06f37d',NULL,1,'2.NHWAFe4Z31AKFgQ4Ewqy5g==|Qm5QygQUCtZHtxd0FGxSRA==|4WCnc30gHplmxiRLQ4XU+WIgYfPtVvmVFyh0wGK+ORI=','2.E8A4wRTTOzGWofCIOaAgaQ==|zjLJB3A2hMXMw4/tmZZ76w==|GfieoK1Lbj8K9Dj2C/reo1tbzeu5pNN1J/E+k0mgaaI=','[]','{"password":"2.a7yaIM8ve7ZeJEAa1E7KNw==|ATeu+JemR1mRESD/qyllHw==|b4fYK/Oni+Z1dt/kJae1sIL/32aK4S4bxq4ro122Yb8=","passwordRevisionDate":null,"totp":null,"uris":[{"match":null,"uri":"2.PIb2jMpyq6AJdDxaGotKDw==|WyXQ1fZTKjOSEpDrRzU0pYJVbRlfjm2WqJikIJ2IifA=|TxdvAD3FsnylNjly0iPjf0KHaXsXaLhkmZKNXvLA01U=","uriChecksum":"2.AhcAUk2pdfYsPmPdS+TxYA==|+fE6/g1SgWGkQLScszDrgGA2RiDOPVGTdSld23PLsiAdxM5vLNtv0XdUTx/dCuA9|Ko7NuwF0arht77hm7pKNc8AgFVdvI5KZO4CI5mNxtxM="}],"username":"2.ko+d3HjFZCOjlwiNp3zAag==|x8faFr/O5nxs35EQPtmoCg==|txsq3UefQaios6inOawrAHNIsJOJmn6xEzFLa2R44B0="}',NULL,NULL,0,NULL);
INSERT INTO "ciphers" VALUES('11981110-bfe6-44b4-8cb8-d1bd900b0475','2026-09-27 21:34:53.506788930','2026-09-27 21:34:53.506998398','abd15dba-ed03-46ca-83e6-af5cda06f37d',NULL,2,'2.OgdOomtyS2EKMKwxRVL+Yw==|M/H8SnhIJh2L6oYTtfLSSg==|BJx0bduCulJk37KMGwocq9gPaXh3kyvxrhuuC7P1zVg=','2.pUbsk2gOHH82EiKcBEzo7g==|B1D2RbnLqfukUn1G63uuZQ==|0u2fG4QmRRlwMOfp8XqM/WbZJOFAP//1fAfwiv6b2+w=','[]','{"type":0}',NULL,NULL,0,NULL);
INSERT INTO "ciphers" VALUES('9c17a515-58c7-4cf5-a95a-f56b8e967f83','2026-09-27 21:34:59.540981818','2026-09-27 21:34:59.542818620',NULL,'97bb884f-372d-46da-9033-dad5b4b95d43',1,'2.h46XGbsD1PbQY2R0BV0sAA==|iIe61wENOdOXiMDh0xGVdg==|ULsXSj/Gf/QM20kKzr5elT+kb3SaQMZ8nKI6uuA2h2U=',NULL,'[]','{"password":"2.Cf4PlsDAbLMk9XXZV+yjDQ==|hDHqVBNItPwbZNQOmALSJw==|VFshn86T0/QljnBsHm71jFOkOevkOPf9PBtgSKLOtCk=","passwordRevisionDate":null,"totp":null,"uris":[],"username":"2.3eZAhfd9EuW0eRN7yTVpdQ==|4tV6ekA1ePMdE8NambIVuA==|K8+8lJmcwxEtbAqwALxu8lqrPmHyFNyOsTorcaveVlA="}',NULL,NULL,0,NULL);
CREATE TABLE ciphers_collections (
  cipher_uuid       TEXT NOT NULL REFERENCES ciphers (uuid),
  collection_uuid TEXT NOT NULL REFERENCES collections (uuid),
  PRIMARY KEY (cipher_uuid, collection_uuid)
);
INSERT INTO "ciphers_collections" VALUES('9c17a515-58c7-4cf5-a95a-f56b8e967f83','ed4a02cd-6c3d-4f0a-af8b-c34fe049100f');
CREATE TABLE collections (
  uuid     TEXT NOT NULL PRIMARY KEY,
  org_uuid TEXT NOT NULL REFERENCES organizations (uuid),
  name     TEXT NOT NULL
, external_id TEXT);
INSERT INTO "collections" VALUES('ed4a02cd-6c3d-4f0a-af8b-c34fe049100f','97bb884f-372d-46da-9033-dad5b4b95d43','2.Y9La/MAwuyZrOppZu3QQ5A==|arAG5rLwrwR2o7wfxpEwvQ==|s6dIbgBTNPoudi8lHzWbVypKdoNOgYHlVURap+pLHaE=',NULL);
CREATE TABLE collections_groups (
  collections_uuid                  TEXT NOT NULL REFERENCES collections (uuid),
  groups_uuid                       TEXT NOT NULL REFERENCES groups (uuid),
  read_only                         BOOLEAN NOT NULL,
  hide_passwords                    BOOLEAN NOT NULL, manage BOOLEAN NOT NULL DEFAULT 0,
  UNIQUE (collections_uuid, groups_uuid)
);
CREATE TABLE "devices" (
	uuid	TEXT NOT NULL,
	created_at	DATETIME NOT NULL,
	updated_at	DATETIME NOT NULL,
	user_uuid	TEXT NOT NULL,
	name	TEXT NOT NULL,
	atype	INTEGER NOT NULL,
	push_token	TEXT,
	refresh_token	TEXT NOT NULL,
	twofactor_remember	TEXT, push_uuid TEXT,
	PRIMARY KEY(uuid, user_uuid),
	FOREIGN KEY(user_uuid) REFERENCES users(uuid)
);
INSERT INTO "devices" VALUES('292b14c5-1b00-4c64-b6c6-4100bd404405','2026-09-27 21:34:36.415460775','2026-09-27 21:34:36.415886882','abd15dba-ed03-46ca-83e6-af5cda06f37d','e2e',9,NULL,'QtcgJ8dLC1-lVTurJXrAFmsCcuXu2tRQExXQqPqegJkDlPsR2YJ-wL40fd-9H-wHqF8klDQIfAmvfkpplnUEpQ==',NULL,'1c29ac66-16b3-4263-9ae2-42b7efe6071c');
INSERT INTO "devices" VALUES('33ff1dcb-215a-4099-88a4-1d0e7d9ab3e6','2026-09-27 21:34:36.795563238','2026-09-27 21:34:36.795812020','02762d19-4ea1-4168-aca5-f2d1b38d80b5','e2e',9,NULL,'taI0sZUZ9V2p73N0AjaGTn_eMItVI5ThGHwPu3CcLSRJ0BeCNdEgc6HgLDK52Ml3U9fYKI-kEVpG2Nb506yCEA==',NULL,'cf6a5aa0-cfef-4ef2-93d8-cf14aaa0a66f');
INSERT INTO "devices" VALUES('0d0de9f9-ef4c-4b26-9ce6-9e4e401dfdc2','2026-09-27 21:34:39.561683893','2026-09-27 21:35:12.310697061','abd15dba-ed03-46ca-83e6-af5cda06f37d','linux',25,NULL,'0ywvStHUHwGmoeSpuakuOOnHDTvpXFeeQ55EFRmVDwYKHI-9QA4noV5eS21jazf6lWGuoMEQfl_KLAdCr2XCsQ==',NULL,'c53e9192-e2c4-4675-a79b-2951f714ed07');
CREATE TABLE emergency_access (
  uuid                      TEXT     NOT NULL PRIMARY KEY,
  grantor_uuid              TEXT     REFERENCES users (uuid),
  grantee_uuid              TEXT     REFERENCES users (uuid),
  email                     TEXT,
  key_encrypted             TEXT,
  atype                     INTEGER  NOT NULL,
  status                    INTEGER  NOT NULL,
  wait_time_days            INTEGER  NOT NULL,
  recovery_initiated_at     DATETIME,
  last_notification_at      DATETIME,
  updated_at                DATETIME NOT NULL,
  created_at                DATETIME NOT NULL
);
INSERT INTO "emergency_access" VALUES('cd2b83ad-1160-48c2-bf65-a468f61f7546','abd15dba-ed03-46ca-83e6-af5cda06f37d','02762d19-4ea1-4168-aca5-f2d1b38d80b5',NULL,'4.VeR4WYrVheLo6oj2DQDj4gn0Oq5jTAdP0TTXVZSI7uv6WTlhD6K+z1uRNkNmE2WR4auyYgQiof4wmSJsH+DpDEvU4jbcqp3R/9TPOpefa0JXlAoDfPZoOFYcTJ/W+LkWvgQJ0ZWSBj97tkGCYdgmmvRht7gyPOF0UPf8dEzdfKeybz2P63vrb1nwUtuNf7GC42kXa77PyUkMdFvK28rICoqmCLrOWm7KObAv44sZKsxfLuwMTZx5C0cVTD+4U/yF6kLWhusq7R//oauYBVhS14hzp68jBxgYcaQPi/20RZx0paoFEtDnF28CyAmcrKGMD43v46WiyxdDT7zsVYow4Q==',0,2,7,NULL,NULL,'2026-09-27 21:34:37.104453582','2026-09-27 21:34:37.096993454');
CREATE TABLE event (
  uuid               TEXT        NOT NULL PRIMARY KEY,
  event_type         INTEGER     NOT NULL,
  user_uuid          TEXT,
  org_uuid           TEXT,
  cipher_uuid        TEXT,
  collection_uuid    TEXT,
  group_uuid         TEXT,
  org_user_uuid      TEXT,
  act_user_uuid      TEXT,
  device_type        INTEGER,
  ip_address         TEXT,
  event_date         DATETIME    NOT NULL,
  policy_uuid        TEXT,
  provider_uuid      TEXT,
  provider_user_uuid TEXT,
  provider_org_uuid  TEXT,
  UNIQUE (uuid)
);
CREATE TABLE favorites (
  user_uuid   TEXT NOT NULL REFERENCES users(uuid),
  cipher_uuid TEXT NOT NULL REFERENCES ciphers(uuid),

  PRIMARY KEY (user_uuid, cipher_uuid)
);
INSERT INTO "favorites" VALUES('abd15dba-ed03-46ca-83e6-af5cda06f37d','f5b8199f-7dd6-4368-8af6-3940d5838def');
CREATE TABLE folders (
  uuid       TEXT     NOT NULL PRIMARY KEY,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  user_uuid  TEXT     NOT NULL REFERENCES users (uuid),
  name       TEXT     NOT NULL
);
INSERT INTO "folders" VALUES('72336182-4b11-4737-a316-2bd53f6c7415','2026-09-27 21:34:46.652690417','2026-09-27 21:34:46.652870261','abd15dba-ed03-46ca-83e6-af5cda06f37d','2.jsvNK16VWgTuzJWSrdEr0g==|a0DR4c9CRphNLaAkWOG5uQ==|VJZ1nRfO8+mbHThI4+rhanOW/WzkifToU06q7uMchZI=');
CREATE TABLE folders_ciphers (
  cipher_uuid TEXT NOT NULL REFERENCES ciphers (uuid),
  folder_uuid TEXT NOT NULL REFERENCES folders (uuid),

  PRIMARY KEY (cipher_uuid, folder_uuid)
);
INSERT INTO "folders_ciphers" VALUES('f5b8199f-7dd6-4368-8af6-3940d5838def','72336182-4b11-4737-a316-2bd53f6c7415');
CREATE TABLE groups (
  uuid                              TEXT NOT NULL PRIMARY KEY,
  organizations_uuid                TEXT NOT NULL REFERENCES organizations (uuid),
  name                              TEXT NOT NULL,
  access_all                        BOOLEAN NOT NULL,
  external_id                       TEXT NULL,
  creation_date                     TIMESTAMP NOT NULL,
  revision_date                     TIMESTAMP NOT NULL
);
CREATE TABLE groups_users (
  groups_uuid                       TEXT NOT NULL REFERENCES groups (uuid),
  users_organizations_uuid          TEXT NOT NULL REFERENCES users_organizations (uuid),
  UNIQUE (groups_uuid, users_organizations_uuid)
);
CREATE TABLE invitations (
    email   TEXT NOT NULL PRIMARY KEY
);
CREATE TABLE org_policies (
  uuid      TEXT     NOT NULL PRIMARY KEY,
  org_uuid  TEXT     NOT NULL REFERENCES organizations (uuid),
  atype     INTEGER  NOT NULL,
  enabled   BOOLEAN  NOT NULL,
  data      TEXT     NOT NULL,

  UNIQUE (org_uuid, atype)
);
CREATE TABLE organization_api_key (
	uuid            TEXT NOT NULL,
    org_uuid	    TEXT NOT NULL,
    atype           INTEGER NOT NULL,
    api_key         TEXT NOT NULL,
	revision_date   DATETIME NOT NULL,
	PRIMARY KEY(uuid, org_uuid),
	FOREIGN KEY(org_uuid) REFERENCES organizations(uuid)
);
CREATE TABLE organizations (
  uuid          TEXT NOT NULL PRIMARY KEY,
  name          TEXT NOT NULL,
  billing_email TEXT NOT NULL
, private_key TEXT, public_key TEXT);
INSERT INTO "organizations" VALUES('97bb884f-372d-46da-9033-dad5b4b95d43','Familie','nyu@example.com','2.l1DMzbuXKTzh4ciIWWwpxw==|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');
CREATE TABLE sends (
  uuid              TEXT NOT NULL   PRIMARY KEY,
  user_uuid         TEXT            REFERENCES users (uuid),
  organization_uuid TEXT            REFERENCES organizations (uuid),

  name              TEXT    NOT NULL,
  notes             TEXT,

  atype             INTEGER NOT NULL,
  data              TEXT    NOT NULL,
  akey               TEXT    NOT NULL,
  password_hash     BLOB,
  password_salt     BLOB,
  password_iter     INTEGER,

  max_access_count  INTEGER,
  access_count      INTEGER NOT NULL,

  creation_date     DATETIME NOT NULL,
  revision_date     DATETIME NOT NULL,
  expiration_date   DATETIME,
  deletion_date     DATETIME NOT NULL,

  disabled          BOOLEAN NOT NULL
, hide_email BOOLEAN);
INSERT INTO "sends" VALUES('60a78314-e221-463b-a4bd-604672bf51b7','abd15dba-ed03-46ca-83e6-af5cda06f37d',NULL,'2.P6BmUlXbqejsoRs6hAS7AQ==|kx3g16NET44wlPY42lUsSA==|uJD7UepAnBSt4xd+TjVxd/AR/PWdT+EGlw32hZzNzfE=',NULL,0,'{"hidden":false,"text":"2.mrZMe8OY1/2dORT7soJl+Q==|F0b82+JaL/9ITLvGYl7uNOKKrsjU+J4HQRQM8Meum20=|QY2oyFdVXB/2eNZMuV+lX/OavWc4f7452e/YF/LNJwQ="}','2.0fuESSnaC9G+y4afmv9nAw==|vOzxmYmE2RxyndZORC3FRK4r/f1F1JALpuFqVWjudA4=|zK3rreTe9G5UzCcEgMIRbjCVisTxCLuUMxryhBEpJYM=',X'1B79778805C9FDBA1202EE504FFEC55205A2B1BDA27FF635FF679A42A8DD07A0',X'14BDC2635CFA88C9F3B07D45CAD98FD6FA4DA9F779726D086F5AFE96A85E2F841B57704CB695CC2E582F02BD3FE7C8B2FB1BB1D3911C2D35A9F14DAA25A6D04F',100000,NULL,0,'2026-09-27 21:35:07.183212749','2026-09-27 21:35:07.224471967',NULL,'2026-10-04 21:35:06.754',0,0);
INSERT INTO "sends" VALUES('ce7b9792-340f-471e-b306-7f6a30e09b89','abd15dba-ed03-46ca-83e6-af5cda06f37d',NULL,'2.4cYudBuUsqxhCJgK3e5G9Q==|rJxa+imYn+mjgXvSjCuI8g==|VUoQ2JrJj2mUNDDc0pi2uGdB+HHTWPkB96mQIAvjXb4=',NULL,1,'{"fileName":"2.mylz6Bv6N89CJeUy7afZFQ==|LFF7cFdVakuh77px+CRYOg==|IAGu5YzdtRQsapR+ED/rHsoAWV1LpSwjpes3odMs9Uk=","id":"1d088644323f76348830f997481347cd13cb279062e8496d7c117768cf07fb25","size":81,"sizeName":"81.00 bytes"}','2.e2xkl4kDL7bYP/YykisE4w==|WtAay3OijtXV5kZifSUh0inLgKEUvtB2l1W5/vw8zoM=|LUln13XZseAKrbjqk2fL8FMLZYNH7s7KDjxkQUyTQrs=',NULL,NULL,NULL,NULL,0,'2026-09-27 21:35:09.504251715','2026-09-27 21:35:09.504355018',NULL,'2026-10-04 21:35:09.159',0,0);
CREATE TABLE sso_auth (
    state               TEXT NOT NULL PRIMARY KEY,
    client_challenge    TEXT NOT NULL,
    nonce               TEXT NOT NULL,
    redirect_uri        TEXT NOT NULL,
    code_response       TEXT,
    auth_response       TEXT,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
, binding_hash TEXT, code_response_error TEXT);
CREATE TABLE sso_users (
  user_uuid           CHAR(36) NOT NULL PRIMARY KEY,
  identifier          TEXT NOT NULL UNIQUE,
  created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY(user_uuid) REFERENCES users(uuid) ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE TABLE twofactor (
  uuid      TEXT     NOT NULL PRIMARY KEY,
  user_uuid TEXT     NOT NULL REFERENCES users (uuid),
  atype      INTEGER  NOT NULL,
  enabled   BOOLEAN  NOT NULL,
  data      TEXT     NOT NULL, last_used INTEGER NOT NULL DEFAULT 0,

  UNIQUE (user_uuid, atype)
);
INSERT INTO "twofactor" VALUES('15f5ac42-8bbb-4c2e-a217-69424f2f868d','02762d19-4ea1-4168-aca5-f2d1b38d80b5',0,1,'GEAP5UN3G2KZB5NJKOIOCRRETA6EDRJY',59684829);
CREATE TABLE twofactor_duo_ctx (
    state      TEXT    NOT NULL,
    user_email TEXT    NOT NULL,
    nonce      TEXT    NOT NULL,
    exp        INTEGER NOT NULL,

    PRIMARY KEY (state)
);
CREATE TABLE twofactor_incomplete (
  user_uuid   TEXT     NOT NULL REFERENCES users(uuid),
  device_uuid TEXT     NOT NULL,
  device_name TEXT     NOT NULL,
  login_time  DATETIME NOT NULL,
  ip_address  TEXT     NOT NULL, device_type INTEGER NOT NULL DEFAULT 14,

  PRIMARY KEY (user_uuid, device_uuid)
);
CREATE TABLE users (
  uuid                TEXT     NOT NULL PRIMARY KEY,
  created_at          DATETIME NOT NULL,
  updated_at          DATETIME NOT NULL,
  email               TEXT     NOT NULL UNIQUE,
  name                TEXT     NOT NULL,
  password_hash       BLOB     NOT NULL,
  salt                BLOB     NOT NULL,
  password_iterations INTEGER  NOT NULL,
  password_hint       TEXT,
  akey                 TEXT     NOT NULL,
  private_key         TEXT,
  public_key          TEXT,
  totp_secret         TEXT,
  totp_recover        TEXT,
  security_stamp      TEXT     NOT NULL,
  equivalent_domains  TEXT     NOT NULL,
  excluded_globals    TEXT     NOT NULL
, client_kdf_type INTEGER NOT NULL DEFAULT 0, client_kdf_iter INTEGER NOT NULL DEFAULT 100000, verified_at DATETIME DEFAULT NULL, last_verifying_at DATETIME DEFAULT NULL, login_verify_count INTEGER NOT NULL DEFAULT 0, email_new TEXT DEFAULT NULL, email_new_token TEXT DEFAULT NULL, enabled BOOLEAN NOT NULL DEFAULT 1, stamp_exception TEXT DEFAULT NULL, api_key TEXT, avatar_color TEXT, client_kdf_memory INTEGER DEFAULT NULL, client_kdf_parallelism INTEGER DEFAULT NULL, external_id TEXT);
INSERT INTO "users" VALUES('abd15dba-ed03-46ca-83e6-af5cda06f37d','2026-09-27 21:34:35.205163858','2026-09-27 21:35:09.516821694','nyu@example.com','nyu',X'8DD659C0B090B1D5645125202546F535C24EB628469467CE8F18135DFF5EA03C',X'6514B79F389CF2E431C3DD9E24D41C3B73511FC8278908DE86388672AB46C02A49875D0E0E4E4F4DED364CD264E0FD3E99D95F66B2D345910335870198C1CABC',600000,NULL,'2.eZhodc4rG/BRk67wfZV7fw==|tIyJ7SXsBTiPOeUtNTll1fG8pl+b90t6aaVmyUa0PFtbjIGFFEy7ULgTiBiOeHQd7WmlN85TnqkjQ3dmsSX6pds9nfL0LjcDwmxcBWE0zRY=|wnPwC9N9YHAVmKcUfqc81omwHZ7ZEG1b1iuq7BXnPp4=','2.ohg2u9naUKAi67BQcGOMTA==|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',NULL,NULL,'059e6675-3ca8-4160-874f-a220d4670d37','[]','[]',0,600000,NULL,NULL,0,NULL,NULL,1,NULL,NULL,NULL,NULL,NULL,NULL);
INSERT INTO "users" VALUES('02762d19-4ea1-4168-aca5-f2d1b38d80b5','2026-09-27 21:34:35.835630801','2026-09-27 21:34:37.092823052','mio@example.com','mio',X'A7E32F75EB640727CBBCD27B0ED0D4BA2FAA8AD7A3717F219F5D167C82962962',X'BBBACBA34354729C3E8BC878FB07A70A5FCF3871C5C66F8524D813939B44BCFD6534D9341BFBA8B72CB1D6A0544D6F8758C937401E5E8BA5241086341A695024',600000,NULL,'2.ZXIMrUaFIE6SqV63WWlp+Q==|iDTJpUiir5XGZU49AwfiwR+/00VqnxxpU01HNiqF4ufo42KRu9Wom8ZA3dzI7G1lVL3eGbix968LaqozaMokogAseT3/82F+0j3YNLOhxQA=|/WkMf6X/ev5qwIi5qPDvxBwiVktJqCcPKvAtKprpjt8=','2.3jHko2O7F21hOK0RI/81sg==|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',NULL,'56ZFULCAP5TO2JRMM4PGTJGDPSBCM3OA','84c5cfde-faca-443c-85d9-ea0305180c19','[]','[]',0,600000,NULL,NULL,0,NULL,NULL,1,NULL,NULL,NULL,NULL,NULL,NULL);
CREATE TABLE users_collections (
  user_uuid       TEXT NOT NULL REFERENCES users (uuid),
  collection_uuid TEXT NOT NULL REFERENCES collections (uuid), read_only BOOLEAN NOT NULL DEFAULT 0, hide_passwords BOOLEAN NOT NULL DEFAULT 0, manage BOOLEAN NOT NULL DEFAULT 0,
  PRIMARY KEY (user_uuid, collection_uuid)
);
CREATE TABLE users_organizations (
  uuid       TEXT    NOT NULL PRIMARY KEY,
  user_uuid  TEXT    NOT NULL REFERENCES users (uuid),
  org_uuid   TEXT    NOT NULL REFERENCES organizations (uuid),

  access_all BOOLEAN NOT NULL,
  akey        TEXT    NOT NULL,
  status     INTEGER NOT NULL,
  atype       INTEGER NOT NULL, reset_password_key TEXT, "external_id" TEXT, invited_by_email TEXT DEFAULT NULL,

  UNIQUE (user_uuid, org_uuid)
);
INSERT INTO "users_organizations" VALUES('e3d592e3-2207-47d5-a127-83a214304e59','abd15dba-ed03-46ca-83e6-af5cda06f37d','97bb884f-372d-46da-9033-dad5b4b95d43',1,'4.VDvTJfEARXdeWiYOCDkI5BB2hTLwgZWbOP0hnQHL8vzedIaQng6iDEWRsNluLhDbpUlxlVoPmm29PPShP8OR9Awiae+21cDE5JNY/KUK+8mqkfYCAN36TAM0xP26YltDG7QUpfS9umvAwtTMFmJBRxmyKCZEZsWzPNL9JSr6XB9uMpyEhdRfG89WVgSAjE9O9fVkbpnneIUlZORYMuGamKoFyBGZRU0gKOSkFAwvrxfEDoylo7WIHeqKIvHMKzigD/974IonlndXGZbBNxmOr4538D/7tTkB4u74Y79tIbo/2C16J7hwujP8W6ArTxQexjb6Uw1bxALAo2xSCJAR0g==',2,0,NULL,NULL,NULL);
COMMIT;
