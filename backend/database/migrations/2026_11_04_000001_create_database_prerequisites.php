<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/*
| citext for users.email, and the trigger function shared by every append-only table
| (docs/database-design.md §5). IF NOT EXISTS / OR REPLACE: db:wipe keeps both objects.
*/
return new class extends Migration
{
    public function up(): void
    {
        DB::statement('CREATE EXTENSION IF NOT EXISTS citext');

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              RAISE EXCEPTION 'table % is append-only', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
            END $$
            SQL);

        DB::statement('REVOKE ALL ON FUNCTION forbid_mutation() FROM PUBLIC');
    }

    public function down(): void
    {
        DB::statement('DROP FUNCTION forbid_mutation()');
        DB::statement('DROP EXTENSION citext');
    }
};
