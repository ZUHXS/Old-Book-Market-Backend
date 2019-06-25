create table app_users( user_id int auto_increment, user_name varchar(40) not null, mail_address varchar(100) not null unique, password_hash varbinary(100), salt varbinary(20) not null, primary key(user_id));
create table books( book_id int auto_increment primary key, posterID int, foreign key(posterID) references app_users(user_id), name varchar(50) not null, exprice double not null, price double not null, ISBN varchar(20) not null, imageURL varchar(400) not null, date DATE not null, description varchar(500) not null, status int);
-- for book status, 0 means 上架中, 1 means 已销售
insert into books(posterID, name, exprice, price, ISBN, imageURL, date, description, status) values(1, '数学分析上', 44.60, 24.00, "9787040295672", "https://img.alicdn.com/imgextra/i2/391838199/O1CN01FjStMt2ARBr7nzqZK_!!0-item_pic.jpg_430x430q90.jpg", now(), "真心求出，上面还有我的笔记，我的数分最后97分", 0);
insert into books(posterID, name, exprice, price, ISBN, imageURL, date, description, status) values(3, '计算机组成与设计：硬件/软件接口', 139.00, 56.80, "9787111608943", "https://img.alicdn.com/imgextra/i4/2130152348/O1CN011TDQQN43LtwrFKn_!!2130152348-2-item_pic.png_430x430q90.jpg", now(), "七成新，上面有三代学长的笔记以及Patt的亲笔签名", 0);
insert into books(posterID, name, exprice, price, ISBN, imageURL, date, description, status) values(3, 'PHP7内核剖析', 89.00, 30.00, "9787121328107", "https://img.alicdn.com/imgextra/i2/2695809921/O1CN01E7wNQp2N9rtuhuZFZ_!!0-item_pic.jpg_430x430q90.jpg", now(), "超棒的PHP入门教程", 0);
insert into books(posterID, name, exprice, price, ISBN, imageURL, date, description, status) values(5, 'PHP7内核剖析', 17.50, 7.00, "9787020135639", "https://img.alicdn.com/imgextra/i1/859515618/TB2X4pNih9YBuNjy0FfXXXIsVXa_!!859515618.jpg_430x430q90.jpg", now(), "史铁生先生充满哲思又极为人性化的代表作之一", 0);
insert into books(posterID, name, exprice, price, ISBN, imageURL, date, description, status) values(5, '鸟哥的Linux私房菜', 86.80, 40.50, "9787115472588", "https://img.alicdn.com/imgextra/i4/1049653664/TB2U2AwaNTpK1RjSZFGXXcHqFXa_!!1049653664-0-item_pic.jpg_430x430q90.jpg", now(), "超经典的Linux入门书", 0);
insert into books(posterID, name, exprice, price, ISBN, imageURL, date, description, status) values(1, '长夜难明', 34.6, 16, "9787222143975", "https://img.alicdn.com/imgextra/i3/TB1u9c9OFXXXXahXpXXXXXXXXXX_!!0-item_pic.jpg_430x430q90.jpg", now(), "紫金陈最新力作，强推", 1);
insert into books(posterID, name, exprice, price, ISBN, imageURL, date, description, status) values(1, '深入理解Linux内核', 71.5, 30, "9787508353944", "https://img.alicdn.com/imgextra/i2/1879601488/O1CN0192yqPY1MrXrYDngOM_!!0-item_pic.jpg_430x430q90.jpg", now(), "Linux内核讲的最清楚的一本书", 1);
insert into books(posterID, name, exprice, price, ISBN, imageURL, date, description, status) values(1, '风流去', 37, 17, "9787500685623", "https://img.alicdn.com/imgextra/i3/101450072/O1CN01U6SGEx1CP1281GhIt_!!0-item_pic.jpg_430x430q90.jpg", now(), "从先秦到魏晋南北朝，从圣贤到文臣，从君子到小人，从英雄到隐士，作者为我们一层层打开了中国传统知识分子或高贵或痛苦的灵魂", 1);


create table message( message_id int auto_increment primary key, from_id int, foreign key(from_id) references app_users(user_id), to_id int, foreign key(to_id) references app_users(user_id), date DATETIME not null, content varchar(1000) not null);
insert into message(from_id, to_id, date, content) value (1, 3, now(), '请问我上次购买的数学分析下发货了吗？');
insert into message(from_id, to_id, date, content) value (3, 1, now(), '发了');
insert into message(from_id, to_id, date, content) value (3, 1, now(), '我帮你查查快递单号');
insert into message(from_id, to_id, date, content) value (3, 1, now(), '寄的是顺丰，单号是xxx');
insert into message(from_id, to_id, date, content) value (3, 1, now(), '你查询一下？');
insert into message(from_id, to_id, date, content) value (1, 3, now(), 'okk我看到了，谢谢啊');
create table request( request_id int auto_increment primary key, user_id int, foreign key(user_id) references app_users(user_id), title varchar(100) not null, content varchar(1000) not null, date DATE not null);
insert into request(user_id, title, content, date) value (3, "求购数学分析", "多少钱都行，急求", now());
insert into request(user_id, title, content, date) value (3, "想要一本普通物理学", "考试需要", now());
insert into request(user_id, title, content, date) value (3, "有没有好书推荐？", "希望是文学史上的经典名著，可以私聊", now());
insert into request(user_id, title, content, date) value (3, "想入门PHP，有推荐的入门书吗？", "非CS专业，希望可以讲的浅显易懂", now());
insert into request(user_id, title, content, date) value (5, "有没有入门信息安全的图书？", "比如道哥的白帽子讲信息安全那种书", now());

create table orders( order_id int auto_increment primary key, customer_id int, foreign key(customer_id) references app_users(user_id), seller_id int, foreign key(seller_id) references app_users(user_id), book_id int, foreign key(book_id) references books(book_id), order_status int, start_date DATE not null, end_date DATE);
-- for order_status, 0 for waiting for seller to confirm, 1 for waiting for customer to confirm, 2 for finished
insert into orders( customer_id, seller_id, book_id, order_status, start_date) values(3, 1, 6, 0, now());
insert into orders( customer_id, seller_id, book_id, order_status, start_date) values(3, 1, 7, 1, now());
insert into orders( customer_id, seller_id, book_id, order_status, start_date) values(3, 1, 8, 2, now());