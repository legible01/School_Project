#include "widget.h"
#include "ui_widget.h"
#include <QMessageBox>

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
    pb_status();

}

Widget::~Widget()
{
    delete ui;
}

void Widget::pb_status()
{
    ui->pbYul->setEnabled(money >= 250);
    ui->pbCoffee->setEnabled(money >= 200);
    ui->pbTea->setEnabled(money >= 100);
    ui->pbReset->setEnabled(money > 0);
}

void Widget::refund_money()
{
    remain_money = ui->leMoney->intValue();

    int change_500;
    int change_100;
    int change_50;
    int change_10;

    return_money_change(&change_500,500);
    return_money_change(&change_100,100);
    return_money_change(&change_50,50);
    return_money_change(&change_10,10);

    QMessageBox message_box;
    message_box.setText(QString("remain 500 * %1,  100 * %2,  50 * %3,  10 * %4 ").arg(change_500).arg(change_100).arg(change_50).arg(change_10));
    message_box.exec();

}
void Widget::return_money_change(int* money_change,int value)
{
    *money_change = money / value;
    money %= value;
}
void Widget::on_pbReset_clicked()
{
    refund_money();
    money = 0;
    ui->leMoney->display(money);
    pb_status();
}

void Widget::input_money(int value)
{
    money += value;
    ui->leMoney->display(money);
    pb_status();
}

void Widget::on_pb500_clicked()
{
    input_money(500);
}

void Widget::on_pb100_clicked()
{
    input_money(100);
}

void Widget::on_pb50_clicked()
{
    input_money(50);
}

void Widget::on_pb10_clicked()
{
    input_money(10);
}

void Widget::on_pbCoffee_clicked()
{
    pay_money(200);
}

void Widget::on_pbTea_clicked()
{
    pay_money(100);
}

void Widget::on_pbYul_clicked()
{
    pay_money(250);
}

void Widget::pay_money(int value)
{
        money-=value;
        ui->leMoney->display(money);
        pb_status();
}




