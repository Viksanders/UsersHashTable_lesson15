#pragma once
#include <iostream>
#include <string>
#include "SHA1.h"

enum enPairStatus
{
    isFree,
    engaged,
    deleted
};

const int hash_size = 5;

struct Pair
{
    Pair()
    {
        m_name = "";
        m_hash_password = nullptr;
        m_status = isFree;
    }
    Pair(std::string& name, uint* hash_password)
    {
        m_name = name;
        m_hash_password = new uint[hash_size];
        for (int i = 0; i < hash_size; i++)
        {
            m_hash_password[i] = hash_password[i];
        }
        m_status = engaged;
    };
    ~Pair()
    {
        delete[] m_hash_password;
    }
    Pair& operator = (const Pair& other)
    {
        m_name = other.m_name;
        delete[] m_hash_password;
        m_hash_password = new uint[hash_size];
        for (int i = 0; i < hash_size; i++)
        {
            m_hash_password[i] = other.m_hash_password[i];
        }
        m_status = other.m_status;
        return *this;
    }
    std::string m_name;           //имя пользователя, он же ключ
    uint* m_hash_password;          //хэш пароля, оно же значение
    enPairStatus m_status;        //статус ячейки: пуста, занята, удалена
};

class UsersHT
{
public:
    UsersHT();
    ~UsersHT();
    void reg_user(std::string& name, std::string& password);
    void add_user(std::string& name, uint* hash_password);
    void print_everything();                            //выводит всё, вообще ВСЁ
    bool login_user(std::string& name, std::string& password);
    void del_user(std::string& name);                   //удаляет пользователя из базы
    uint* find_user_hash(std::string& name);          //выдает хэш от пароля пользователя при запросу по имени
    bool is_registered(std::string& name);          //проверяет, есть ли уже пользователь с таким именем
    void resize();
    void shrink();                                  //то же, что и ресайз, но уменьшает массив в 2 раза, когда накапливается слишком много удаленных элементов
    int hash_func(std::string& name, int offset);    //хэш-функция для доступа к таблице
private:
    Pair* m_array;    //массив с пользователям
    int m_size;       //размер массива
    int m_count;      //количество пользователей на данный момент
    int m_del_count;  //количество удаленных пользователей, когда их количество перевалит за половина от размера массива - делаем ресайз
};

