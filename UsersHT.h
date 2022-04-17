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
    std::string m_name;           //��� ������������, �� �� ����
    uint* m_hash_password;          //��� ������, ��� �� ��������
    enPairStatus m_status;        //������ ������: �����, ������, �������
};

class UsersHT
{
public:
    UsersHT();
    ~UsersHT();
    void reg_user(std::string& name, std::string& password);
    void add_user(std::string& name, uint* hash_password);
    void print_everything();                            //������� ��, ������ �Ѩ
    bool login_user(std::string& name, std::string& password);
    void del_user(std::string& name);                   //������� ������������ �� ����
    uint* find_user_hash(std::string& name);          //������ ��� �� ������ ������������ ��� ������� �� �����
    bool is_registered(std::string& name);          //���������, ���� �� ��� ������������ � ����� ������
    void resize();
    void shrink();                                  //�� ��, ��� � ������, �� ��������� ������ � 2 ����, ����� ������������� ������� ����� ��������� ���������
    int hash_func(std::string& name, int offset);    //���-������� ��� ������� � �������
private:
    Pair* m_array;    //������ � �������������
    int m_size;       //������ �������
    int m_count;      //���������� ������������� �� ������ ������
    int m_del_count;  //���������� ��������� �������������, ����� �� ���������� ��������� �� �������� �� ������� ������� - ������ ������
};

