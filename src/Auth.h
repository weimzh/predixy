/*
 * predixy - A high performance and full features proxy for redis.
 * Copyright (C) 2017 Joyield, Inc. <joyield.com@gmail.com>
 * All rights reserved.
 */

#ifndef _PREDIXY_AUTH_H_
#define _PREDIXY_AUTH_H_

#include <map>
#include <set>
#include <vector>
#include <pthread.h>
#include "Predixy.h"

class Auth :
    public RefCntObj<Auth>
{
public:
    typedef Alloc<Auth, Const::AuthAllocCacheSize> Allocator;
    Auth(int mode = Command::Read|Command::Write|Command::Admin);
    Auth(const AuthConf& conf);
    ~Auth();
    const String& password() const
    {
        return mPassword;
    }
    bool IPAllowed(const String& peer) const;
    bool permission(Request* req, const String& key) const;
private:
    String mPassword;
    int mMode;
    typedef std::set<String> KeyPrefixSet;
    KeyPrefixSet* mReadKeyPrefix;
    KeyPrefixSet* mWriteKeyPrefix;
    KeyPrefixSet* mIPWhiteList;
};

class Authority
{
public:
    Authority();
    ~Authority();
    bool hasAuth() const
    {
        return !mAuthMap.empty();
    }
    Auth* get(const String& pd) const
    {
        pthread_rwlock_rdlock((pthread_rwlock_t*)&mLock);
        auto it = mAuthMap.find(pd);
        Auth* ret = it == mAuthMap.end() ? nullptr : it->second;
        if (ret)
        {
            ret->ref();
        }
        pthread_rwlock_unlock((pthread_rwlock_t*)&mLock);
        return ret;
    }
    Auth* getDefault() const
    {
        pthread_rwlock_rdlock((pthread_rwlock_t*)&mLock);
        auto ret = mDefault;
        ret->ref();
        pthread_rwlock_unlock((pthread_rwlock_t*)&mLock);
        return ret;
    }
    void add(const AuthConf& ac);
    void lock()
    {
        pthread_rwlock_wrlock(&mLock);
    }
    void unlock()
    {
        pthread_rwlock_unlock(&mLock);
    }
private:
    std::map<String, Auth*> mAuthMap;
    Auth* mDefault;
    static Auth AuthAllowAll;
    static Auth AuthDenyAll;
    pthread_rwlock_t mLock;
};

#endif
