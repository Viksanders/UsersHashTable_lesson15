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

    ht.reg_user(n1, pass1); ht.reg_user(n2, pass2); //сначала добавляем двух новых юзеров
    ht.print_everything();                          //и выводим на экран содержимое хэш таблицы, в том числе с пустыми ячейками, чтобы видеть как распределяется
    
    //теперь добавим ещё кучу пользователей, чтобы посмотреть, как сработает ресайз
    ht.reg_user(n3, pass3); ht.reg_user(n4, pass4); ht.reg_user(n5, pass5); ht.reg_user(n6, pass6); ht.reg_user(n7, pass7); ht.reg_user(n8, pass8);
    ht.print_everything();  //и снова всё выведем

    //попробуем регунть пользователя с занятым именем, увидим, что не получается
    ht.reg_user(n8, pass8);

    //теперь попробуем удалить пользователя, которого изначально не было в таблице
    std::string nouser = "abc";
    ht.del_user(nouser);        //увидим, что нет такого пользователя, будет выведено соответствующее сообщение
    ht.del_user(n8);            //уже имеющийся пользователь прекрасно удаляется
    ht.print_everything();      //снова всё напечатаем

    //теперь удаляем кучу пользователей, чтобы посмотреть, как хэш-таблица опять ресайзнется (на этот раз сожмётся)
    ht.del_user(n7);    ht.del_user(n6);    ht.del_user(n5);    ht.del_user(n4);    ht.del_user(n3);
    std::cout << "\n\n";
    ht.print_everything();

    //попытки логина, см пояснения в комментарии ниже
    std::string wrong_pass1 = "123";
    std::cout << ht.login_user(n1, pass1) << "\n";      //должно выдать 1, логин и пароль верные
    std::cout << ht.login_user(n2, pass2) << "\n";      //должно выдать 1, логин и пароль верные
    std::cout << ht.login_user(n1, wrong_pass1) << "\n";    //должно выдать 0, логин верен и пароль неверен
    std::cout << ht.login_user(n8, pass8) << "\n";      //должно выдать 0, т.к. пользователь 8 удалён


    //та самая проверка, что хэши для одинаковых паролей совпадают
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
