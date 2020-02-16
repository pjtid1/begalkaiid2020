# begalkaiid2020
BEGAL TIKET KAI

# begalkaiid2020
This tools used to book ticket smartly
This program is secret software: you cant redistribute it and/or modify. 
It under the terms of the Himacrot License as published by the Secret Software Society, 
either version 3 of the License, or any later version.


    Usage: python kereto_jowo.py retry_num use_proxy(0 if no, 1 if yes) set_seat(0 if no, 1 if yes) recipe


## with docker

1. clone this repo
2. cd kai_backd
3. build docker
    ```
    docker build -t kereto_jowo .
    ```
    
4. access folder with json data
5. run script with docker
    ```
    unix    -> docker run --rm -v "$PWD":/data kereto_jowo 1 0 0 /data/recipe.txt
    windows -> docker run --rm -v %cd%:/data kereto_jowo 1 0 0 /data/recipe.txt
    ```

6. profit

## with katacoda -> free docker playground online

1. open link https://www.katacoda.com/courses/docker/playground
2. create folder projects
    ```
    mkdir projects
    ```
3. cd to folder projects
    ```
    cd projects
    ```
4. git setting to folder projects
    ```
    git init
    ```
5. pull this repo
    ```
    git pull https://github.com/macbook47/kereto_jowo/
    ```
6. edit recipe.txt with your data -> kalau gak tau vi, googling dl aja :P
    ```
    vi recipe.txt
    ```
    kalau susah pake vi, bisa install dulu nano -> apt-get install nano
    ```
    apt-get install nano
    nano recipe.txt
    ```
7. build docker
    ```
    docker build -t kereto_jowo .
    ```
8. run docker
    ```
    docker run kereto_jowo 1 0 0 recipe.txt
    ```
9. profit


## json recipe detail

line 1 is user pass kai mobile -> 
```
{"email": -> email mobile kai, "password": -> password mobile kai, "platform" :"mobile" -> jangan diganti}
```


line 2 is passenger data ->
```
{
  "address": "Gedung IT BRI Jakarta", -> alamat mu ndes, ojo di isi akhirat yo
  
  "date_return": "20180318", -> your date return -> isi aja kayak dep date
  
  "dep_date": "2018-03-18", -> your depature date -> tgl keberangkatan yyyy-mm-dd
  
  "des": "CN", -> stasiun tujuan -> untuk kode cek aja di web kai
  
  "email": "macbook.47@gmail.com", -> email nanti yg nerima notif
  
  "isreturn": false, -> kalo mau bolak balik
  
  "name": "Jehan Rachmatika", -> nama yg pesen
  
  "num_pax_adult": "2", -> jumlah penumpang dewasa -> menentukan jumlah array di penumpang dewasa
  
  "num_pax_infant": "1", -> jumlah penumang anak -> menentukan jumlah array di penumpang anak, klo 0 gak usah diisi json nya
  
  "org": "GMR", -> stasiun keberangkatan -> untuk kode cek aja di web kai
  
  "passenger": [ -> data penumpang
      {
        "idnum": "3201111101110009",
        "psgtype": "A",
        "name": "harry potter"
      },
      {
        "idnum": "347101010111003",
        "psgtype": "A",
        "name": "marvolo riddle"
      }
  ],
  
  "phone": "085111111110", -> no hape pemesan
  
  "subclass": "X", -> kelas keretanya -> kode bisa di liat di web kai
  
  "subclass_return": "", -> kelas kereta klo pesen bolak balik
  
  "train_no": "16", -> kode kereta nya -> kode bisa di liat di web kai
  
  "train_no_return": 0
  
}
```

line 3 is search seat data ->

```
{"adult": "3","child": 0,"date": "2019-03-21","date_return": "20190321","des": "BD","des_is_city": false,"infant": 0,"isreturn": false,"org": "GMR","org_is_city": false}
```



line 4 is seat data -> jumlah aray json sesuai dg penumpang dewasa -> masih ada bug -> coba2 sendiri aja yes :P

```
{"seat": "9A","wagon_code": "EKS","wagon_no": "3"},{"seat": "9B","wagon_code": "EKS","wagon_no": "3"}
```



# support us

support us to make better tools :

<a href="https://www.patreon.com/bePatron?u=17793626" data-patreon-widget-type="become-patron-button">Become a Patron!</a>
