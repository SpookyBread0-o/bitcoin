// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_ADDRESSBOOKMAN_H
#define BITCOIN_WALLET_ADDRESSBOOKMAN_H

#include <script/standard.h>
#include <sync.h>

#include <functional>
#include <map>

/** Address book data */
class CAddressBookData
{
private:
    bool m_change{true};
    std::string m_label;
public:
    std::string purpose;

    CAddressBookData() : purpose("unknown") {}

    typedef std::map<std::string, std::string> StringMap;
    StringMap destdata;

    bool IsChange() const { return m_change; }
    const std::string& GetLabel() const { return m_label; }
    void SetLabel(const std::string& label) {
        m_change = false;
        m_label = label;
    }
};

namespace wallet {
    class WalletBatch;
}

class AddressBookMan {
private:
    mutable RecursiveMutex cs_addrbook;
    std::map<CTxDestination, CAddressBookData> m_address_book GUARDED_BY(cs_addrbook);

    // return nullptr if not found
    CAddressBookData* GetEntry(const CTxDestination&) EXCLUSIVE_LOCKS_REQUIRED(cs_addrbook);

public:

    /**
     * Retrieves the address book entry.
     * std::nullopt if there is no item for the destination.
     */
    std::optional<CAddressBookData> Find(const CTxDestination&) const;

    /**
     * Returns true if the key exist and 'allow_change' matches the entry.
     */
    bool Has(const CTxDestination& dest, bool allow_change = false) const;

    /**
     * Walk-through the entries.
     * Stops when the provided 'ListAddrBookFunc' returns false.
     */
    using ListAddrBookFunc = std::function<void(const CTxDestination& dest, const std::string& label, const std::string& purpose, bool is_change)>;
    void ForEachAddrBookEntry(const ListAddrBookFunc& func) const;

    /**
     *  Store/Update a new entry in the address book map and database.
     *  Replacing any previously existing value.
     *
     *  If 'purpose' is empty, the purpose field will not be updated.
     *  Note: be REALLY careful with the purpose field.
     */
     bool Put(wallet::WalletBatch& batch, const CTxDestination& dest, const std::string& label, const std::string& purpose);

     /**
      * Removes the entry associated with the specified destination
      * from the map and database.
      */
     bool Delete(wallet::WalletBatch& batch, const CTxDestination& dest);

     /** Marks the destination as 'used' */
     bool SetDestUsed(wallet::WalletBatch& batch, const CTxDestination& dest, bool used);
     /** Returns true if the destination was previously marked as 'used' */
     bool IsDestUsed(const CTxDestination& dest) const;

     std::vector<std::string> GetEntriesByDestDataPrefix(const std::string& prefix) const;
     bool SetEntryDestData(wallet::WalletBatch& batch, const CTxDestination& dest,
                          const std::string key,  const std::string& id, const std::string& value);

     /** Adds a destination data tuple to the store, without saving it to disk */
     void LoadDestData(const CTxDestination& dest, const std::string& key, const std::string& value);
     /** Adds destination label to the store, without saving it to disk */
     void LoadEntryLabel(const CTxDestination& dest, const std::string& label);
     /** Adds destination purpose to the store, without saving it to disk */
     void LoadEntryPurpose(const CTxDestination& dest, const std::string& purpose);
     /** Return address book size */
     int GetSize() const;
};

#endif // BITCOIN_WALLET_ADDRESSBOOKMAN_H
