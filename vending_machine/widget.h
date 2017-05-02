#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QMessageBox>

namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = 0);
    ~Widget();

private slots:

    void on_pbReset_clicked();

    void on_pb500_clicked();

    void on_pb100_clicked();

    void on_pb50_clicked();

    void on_pb10_clicked();

    void on_pbCoffee_clicked();

    void on_pbTea_clicked();

    void on_pbYul_clicked();



private:
    Ui::Widget *ui;

    int money_status;
    int remain_money;

    void return_money_change(int* money_change,int value);
    void pb_status();
    void refund_money();
    void input_money(int value);
    void pay_money(int value);
};

#endif // WIDGET_H
