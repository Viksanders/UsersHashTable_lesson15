#include "UsersHT.h"

UsersHT::UsersHT()
{
    m_count = 0;
    m_del_count = 0;
    m_size = 5;
    m_array = new Pair[m_size];
}

UsersHT::~UsersHT()
{
    delete[] m_array;
}

int UsersHT::hash_func(std::string& name, int offset)
{
    const double A = 0.618;
    const int B = 16;
    int sum = 0;
    for (size_t i = 0; i < name.length(); i++)
    {
        sum += static_cast<int>(name[i]);
    }
    return (int(B * (A * sum - int(A * sum))) + offset * offset) % m_size;  //����� ������������� ������������, ���� ���-������� int(B*(A*sum - int(A*sum))) - ������� ���������
}

void UsersHT::reg_user(std::string& name, std::string& password)
{
    if (is_registered(name))    //���� ��� ���� � ����� ������, �� ������ �� ������
    {
        std::cout << "\nAlready here\n\n";
        return;
    }

    //������� ��� ������
    uint* hash_to_add = sha1_str(password);
    add_user(name, hash_to_add);    //��������� �����
    delete[] hash_to_add;
}

void UsersHT::add_user(std::string& name, uint* hash_password)
{
    /*
    if (is_registered(name))    //�������� ��� �������� ����� �� ������
    {
        std::cout << "\nAlready here\n\n";
        return;
    }
    */
    int index = -1;
    int i = 0;
    for (; i < m_size; i++)
    {
        index = hash_func(name, i);
        if (m_array[index].m_status == isFree) break;
    }
    if (i >= m_size)    //���� ������ ��������, ��
    {
        resize();       //������ ������
        add_user(name, hash_password);    //� ��������� ������ ������������ � ��� ����������� ������
    }
    else
    {
        m_array[index] = Pair(name, hash_password);
        m_count++;
    }
}

bool UsersHT::login_user(std::string& name, std::string& password)
{
    int index = -1;
    int i = 0;
    for (; i < m_size; i++)
    {
        index = hash_func(name, i);
        if ((m_array[index].m_status == engaged) && (m_array[index].m_name == name))
        {
            //��� ������� ���
            uint* hash_to_check = sha1_str(password);
            if (two_hashes_compare(m_array[index].m_hash_password, hash_to_check) == true)
            {
                delete[] hash_to_check;
                return true;    //�� �����!
            }
            else
            {
                delete[] hash_to_check;
                return false;          //�������� ������
            }
        }
    }
    return false;   //��� ������������ � ����� ������
}

void UsersHT::resize()
{
    int old_size = m_size;
    Pair* old_array = m_array;
    m_count = 0;                //�������� ������� ����������� �������������
    m_del_count = 0;            //� �������� ����, ��� ��� ��� �� ����� �������� � ����������� ������
    m_size = m_size * 2;          //����������� ������ � 2 ����
    m_array = new Pair[m_size];

    for (int i = 0; i < old_size; i++)   //��������� ���� ������ ������������� � ����� ������
    {
        //��������� ������������ �� ������� �������, ������ ���� �� �� ���� � �� �����
        if (old_array[i].m_status == engaged) add_user(old_array[i].m_name, old_array[i].m_hash_password);
    }
    delete[] old_array;     //������� ������ ������
}

void UsersHT::shrink()
{
    int old_size = m_size;
    Pair* old_array = m_array;
    m_count = 0;                //�������� ������� ����������� �������������
    m_del_count = 0;            //� �������� ����, ��� ��� ��� �� ����� �������� � ����������� ������
    m_size = m_size / 2;          //��������� ������ � 2 ����
    m_array = new Pair[m_size];

    for (int i = 0; i < old_size; i++)   //��������� ���� ������ ������������� � ����� ������
    {
        //��������� ������������ �� ������� �������, ������ ���� �� �� ���� � �� �����
        if (old_array[i].m_status == engaged) add_user(old_array[i].m_name, old_array[i].m_hash_password);
    }
    delete[] old_array;     //������� ������ ������
}

void UsersHT::print_everything()
{
    for (int i = 0; i < m_size; i++)
    {
        if (m_array[i].m_status != engaged)
        {
            std::cout << "pos: " << i << " is " << m_array[i].m_status << "\n";
            continue;
        }
        else std::cout << "pos: " << i << "   user name: " << m_array[i].m_name << "  with pass hash: " << *(m_array[i].m_hash_password) << "\n";
        //������ ��� ����� �� ������ ������, ��������� ������ ������ ���� ����, �� � �������� ��������, ��� ��� �� ���� 
    }
}

uint* UsersHT::find_user_hash(std::string& name)
{
    int index = -1;
    int i = 0;
    for (; i < m_size; i++)
    {
        index = hash_func(name, i);
        //���� ����� ������������ - ���������� ��� �� ��� ������
        if ((m_array[index].m_status == engaged) && (m_array[index].m_name == name)) return m_array[index].m_hash_password;
    }
    return nullptr;    //���� ���, �� ����� ����� ������������� ��� ������
}

bool UsersHT::is_registered(std::string& name)
{
    int index = -1;
    int i = 0;
    for (; i < m_size; i++)
    {
        index = hash_func(name, i);
        if ((m_array[index].m_status == engaged) && (m_array[index].m_name == name)) return true;
    }
    return false;
}

void UsersHT::del_user(std::string& name)
{
    int index = -1;
    int i = 0;
    bool flag = false;
    for (; i < m_size; i++)
    {
        index = hash_func(name, i);
        if ((m_array[index].m_status == engaged) && (m_array[index].m_name == name))
        {
            m_array[index].m_status = deleted;
            m_count--;
            m_del_count++;
            flag = true;
        }
    }
    if (flag == false)
    {
        std::cout << "\nNo user with name: " << name << "\n\n";
        return;
    }

    if (m_del_count >= (m_size >> 1)) shrink();
}
