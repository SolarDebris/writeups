alp = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-+"
test = "51sZIpMhSrd7HBUgRmCQPy23vu6joc-LEXT9KzbaOxefAtY8l+kJ0GNw4WnqFiDV"
enc_flag = "m_ERpmfrNkekU4_4asI_Tra1e_4l_c4_GCDlryidS3{Ptsu9i}13Es4V73M4_ans"
order = []

for a in alp:
    order.append(test.index(a))
flag = ""
for o in order:
    flag += enc_flag[o]

print(order)
print(flag)
