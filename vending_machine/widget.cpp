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
    int value = ui->leMoney->text().toInt();
    ui->pbTea->setEnabled(false);
    ui->pbCoffee->setEnabled(false);
    ui->pbYul->setEnabled(false);

    if(value >= 250)
        ui->pbYul->setEnabled(true);
    if(value >= 200)
        ui->pbCoffee->setEnabled(true);
    if(value >= 100)
        ui->pbTea->setEnabled(true);
}


void Widget::refund_money()
{
    remain_money = ui->leMoney->text().toInt();
    int change_500=0;
    int change_100=0;
    int change_50=0;
    int change_10=0;

    while(remain_money !=0){
        if(remain_money >= 500){
            return_money_change(&change_500,500);
            continue;
        }
        if(remain_money >= 100){
            return_money_change(&change_100,100);
            continue;
        }
        if(remain_money >= 50){
            return_money_change(&change_50,50);
            continue;
        }
        if(remain_money >= 10){
            return_money_change(&change_10,10);
            continue;
        }
    }

    QMessageBox message_box;
    message_box.setText(QString("remain 500 * %1,  100 * %2,  50 * %3,  10 * %4 ").arg(change_500).arg(change_100).arg(change_50).arg(change_10));
    message_box.exec();

}
void Widget::return_money_change(int* money_change,int value)
{
    *money_change = remain_money / value;
    remain_money %= value;
}
void Widget::on_pbReset_clicked()
{
    refund_money();
    ui->leMoney->setText("0");
    pb_status();
}

void Widget::input_money(int value)
{
    ui->leMoney->setText(QString::number(ui->leMoney->text().toInt()+value));
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
        ui->leMoney->setText(QString::number(ui->leMoney->text().toInt()-value));
        pb_status();
}




