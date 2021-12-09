#include "pocketdb/migrations/web.h"

namespace PocketDb
{
    PocketDbWebMigration::PocketDbWebMigration() : PocketDbMigration()
    {
        _tables.emplace_back(R"sql(
            create table if not exists Tags
            (
              Id    integer primary key,
              Lang  text not null,
              Value text not null
            );
        )sql");

        _tables.emplace_back(R"sql(
            create table if not exists TagsMap
            (
              ContentId   int not null,
              TagId       int not null,
              primary key (ContentId, TagId)
            );
        )sql");

        _tables.emplace_back(R"sql(
            create table if not exists ContentMap
            (
                ContentId int not null,
                FieldType int not null,
                primary key (ContentId, FieldType)
            );
        )sql");

        _tables.emplace_back(R"sql(
            create virtual table if not exists Content using fts5
            (
                Value, tokenize = 'porter unicode61 remove_diacritics 1'
            );
        )sql");

        // TAWMAZ:
        _tables.emplace_back(R"sql(
            create virtual table if not exists Content_v using fts5vocab (Content, col);
        )sql");

        _tables.emplace_back(R"sql(
            create virtual table if not exists SpellCheck using spellfix1;
        )sql");

        _tables.emplace_back(R"sql(
            insert into SpellCheck(word, rank) select term, doc from Content_v where term not in (select word from SpellCheck_vocab);
        )sql");

        _indexes = R"sql(
            create unique index if not exists Tags_Lang_Value on Tags (Lang, Value);
            create index if not exists Tags_Lang_Id on Tags (Lang, Id);
            create index if not exists Tags_Lang_Value_Id on Tags (Lang, Value, Id);
            create index if not exists TagsMap_TagId_ContentId on TagsMap (TagId, ContentId);
        )sql";
    }
}