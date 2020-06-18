// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_DB_H
#define BITCOIN_WALLET_DB_H

#include <clientversion.h>
#include <fs.h>
#include <streams.h>

#include <string>

/** Given a wallet directory path or legacy file path, return path to main data file in the wallet database. */
fs::path WalletDataFilePath(const fs::path& wallet_path);
void SplitWalletPath(const fs::path& wallet_path, fs::path& env_directory, std::string& database_filename);

/** RAII class that provides access to a WalletDatabase */
class DatabaseBatch
{
private:
    virtual bool ReadKey(CDataStream& key, CDataStream& value) = 0;
    virtual bool WriteKey(CDataStream& key, CDataStream& value, bool overwrite=true) = 0;
    virtual bool EraseKey(CDataStream& key) = 0;
    virtual bool HasKey(CDataStream& key) = 0;

public:
    explicit DatabaseBatch() {}
    virtual ~DatabaseBatch() {}

    DatabaseBatch(const DatabaseBatch&) = delete;
    DatabaseBatch& operator=(const DatabaseBatch&) = delete;

    virtual void Flush() = 0;
    virtual void Close() = 0;

    template <typename K, typename T>
    bool Read(const K& key, T& value)
    {
        // Key
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        bool success = false;
        bool ret = ReadKey(ssKey, ssValue);
        if (ret) {
            // Unserialize value
            try {
                ssValue >> value;
                success = true;
            } catch (const std::exception&) {
                // In this case success remains 'false'
            }
        }
        return ret && success;
    }

    template <typename K, typename T>
    bool Write(const K& key, const T& value, bool fOverwrite = true)
    {
        // Key
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;

        // Value
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.reserve(10000);
        ssValue << value;

        // Write
        return WriteKey(ssKey, ssValue, fOverwrite);
    }

    template <typename K>
    bool Erase(const K& key)
    {
        // Key
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;

        // Erase
        return EraseKey(ssKey);
    }

    template <typename K>
    bool Exists(const K& key)
    {
        // Key
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;

        // Exists
        return HasKey(ssKey);
    }

    virtual bool CreateCursor() = 0;
    virtual bool ReadAtCursor(CDataStream& ssKey, CDataStream& ssValue, bool& complete) = 0;
    virtual void CloseCursor() = 0;
    virtual bool TxnBegin() = 0;
    virtual bool TxnCommit() = 0;
    virtual bool TxnAbort() = 0;
};

#endif // BITCOIN_WALLET_DB_H
