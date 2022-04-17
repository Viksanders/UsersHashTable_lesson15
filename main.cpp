#include <iostream>
#include <string>
#include "SHA1.h"
#include "UsersHT.h"


int main()
{
    UsersHT ht;
    std::string n1 = "a1"; std::string pass1 = "1231";
    std::string n2 = "a2"; std::string pass2 = "123414";
    std::string n3 = "a3"; std::string pass3 = "1231";
    std::string n4 = "a4"; std::string pass4 = "1231";
    std::string n5 = "a5"; std::string pass5 = "1231";
    std::string n6 = "a6"; std::string pass6 = "1231";
    std::string n7 = "a7"; std::string pass7 = "1231";
    std::string n8 = "a8"; std::string pass8 = "1231";

    ht.reg_user(n1, pass1); ht.reg_user(n2, pass2); //������� ��������� ���� ����� ������
    ht.print_everything();                          //� ������� �� ����� ���������� ��� �������, � ��� ����� � ������� ��������, ����� ������ ��� ��������������
    
    //������ ������� ��� ���� �������������, ����� ����������, ��� ��������� ������
    ht.reg_user(n3, pass3); ht.reg_user(n4, pass4); ht.reg_user(n5, pass5); ht.reg_user(n6, pass6); ht.reg_user(n7, pass7); ht.reg_user(n8, pass8);
    ht.print_everything();  //� ����� �� �������

    //��������� ������� ������������ � ������� ������, ������, ��� �� ����������
    ht.reg_user(n8, pass8);

    //������ ��������� ������� ������������, �������� ���������� �� ���� � �������
    std::string nouser = "abc";
    ht.del_user(nouser);        //������, ��� ��� ������ ������������, ����� �������� ��������������� ���������
    ht.del_user(n8);            //��� ��������� ������������ ��������� ���������
    ht.print_everything();      //����� �� ����������

    //������ ������� ���� �������������, ����� ����������, ��� ���-������� ����� ����������� (�� ���� ��� �������)
    ht.del_user(n7);    ht.del_user(n6);    ht.del_user(n5);    ht.del_user(n4);    ht.del_user(n3);
    std::cout << "\n\n";
    ht.print_everything();

    //������� ������, �� ��������� � ����������� ����
    std::string wrong_pass1 = "123";
    std::cout << ht.login_user(n1, pass1) << "\n";      //������ ������ 1, ����� � ������ ������
    std::cout << ht.login_user(n2, pass2) << "\n";      //������ ������ 1, ����� � ������ ������
    std::cout << ht.login_user(n1, wrong_pass1) << "\n";    //������ ������ 0, ����� ����� � ������ �������
    std::cout << ht.login_user(n8, pass8) << "\n";      //������ ������ 0, �.�. ������������ 8 �����


    //�� ����� ��������, ��� ���� ��� ���������� ������� ���������
    std::cout << "\nCheck hash equality for equal passwords\n";
    uint* hash1 = sha1_str(pass1);
    uint* hash2 = sha1_str(pass3);
    std::cout << std::hex << hash1[0] << "    " << hash2[0] << "\n";
    std::cout << std::hex << hash1[1] << "    " << hash2[1] << "\n";
    std::cout << std::hex << hash1[2] << "    " << hash2[2] << "\n";
    std::cout << std::hex << hash1[3] << "    " << hash2[3] << "\n";
    std::cout << std::hex << hash1[4] << "    " << hash2[4] << "\n";
    delete[] hash1;
    delete[] hash2;

    return 0;
}
