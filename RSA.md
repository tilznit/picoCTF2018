# RSA problem solves for picoCTF 2018

Here are my walkthroughs of three RSA problems from [picoCTF 2018](https://picoctf.com/).

First, you should try to understand the [RSA cryptosystem](https://en.wikipedia.org/wiki/RSA_(cryptosystem)). You'll basically be using online tools to solve for the unknown parts of the RSA equation, or other equations that lead to the unknown parts of the RSA equation, and use that info to get the flag. These problems highlight what happens to your encrypted data when RSA isn't properly implemented. Unfortunately, I don't have the original questions for the problems.

## Safe RSA

We are given n, e, and c.

```python
n = 374159235470172130988938196520880526947952521620932362050308663243595788308583992120881359365258949723819911758198013202644666489247987314025169670926273213367237020188587742716017314320191350666762541039238241984934473188656610615918474673963331992408750047451253205158436452814354564283003696666945950908549197175404580533132142111356931324330631843602412540295482841975783884766801266552337129105407869020730226041538750535628619717708838029286366761470986056335230171148734027536820544543251801093230809186222940806718221638845816521738601843083746103374974120575519418797642878012234163709518203946599836959811

e = 3

c = 2205316413931134031046440767620541984801091216351222789180582564557328762455422721368029531360076729972211412236072921577317264715424950823091382203435489460522094689149595951010342662368347987862878338851038892082799389023900415351164773

# c is the ciphertext
# n = pq
```

Googling for `RSA e=3` we can see that this is bad because if the plaintext message is smaller than 3^√n (cubed root of n) then a simple computation of 3^√c will recover the original message (`e` is used in creating the public and private keys).

I tried calculating the cubed root of `c` in python, but I ran into the [floating point error problem](https://en.wikipedia.org/wiki/Floating_point_error_mitigation) which reduces the accuracy of our cubed-root calculation. I found a cubed root calculator that sufficiently handles large values online at [https://www.dcode.fr/cube-root](https://www.dcode.fr/cube-root).

The calculator gave the following value: `13016382529449106065839070830454998857466392684017754632233906857023684751222397`

I was stuck here for a while. A hint on the picoctf forums mentioned to convert it to hex. I tried

```python
m = hex(13016382529449106065839070830454998857466392684017754632233906857023684751222397)
# m = hex encoded plaintext

>>> m
'0x7069636f4354467b655f7734795f7430305f736d3431315f38316236353539667dL'
```
Note the trailing `L` in the returned hex value. Prior to python3 this denotes the value as a [long integer literal](https://stackoverflow.com/questions/11764713/why-do-integers-in-database-row-tuple-have-an-l-suffix). I then went to [cyberchef](https://gchq.github.io/CyberChef/), entered the value minus the trailing L (again, for `type(m)=long` in python) in the input pane. I chose the "from hex" operation with a delimiter of `0x` and was given the flag in the output pane:

`picoCTF{e_w4y_t00_sm411_81b6559f}`

## Supersafe RSA:

We are given n, e, and c.

```python
n = 14568468476432837846531823758196941722524462577948878352231306047102565364099933
e = 65537
c = 7686966029791874563175059394981000840074736771341506547944950743609250244624246
```
This time `e` is large, and cubed-root calculations won't work. Referencing the wikipedia article at the begining of this document, it turns out we'll have to compute the private key `d`.

In order to find `d`, we need to find `p` & `q`. To find `p` & `q` we need to factor `n` and look for primes. I found a neat online tool at [https://www.alpertron.com.ar/ECM.HTM](https://www.alpertron.com.ar/ECM.HTM) that will do this for us. We get

```python
p = 103419850061766398711688540905436955187
q = 140867236490209335558539611454420246899759
```
Now we can find `d` after computing the least common multiple (lcm) of the product of`p-1` and `q-1` ([Carmichael's totient function](https://en.wikipedia.org/wiki/Carmichael_function)). I found [https://www.dcode.fr/lcm](https://www.dcode.fr/lcm) to be helpful here. IIRC this calculation crushed my computer, which has the computing power of a doorstop. Oh well, you gotta use what you have.

`λ(n)=lcm(p-1,q-1) = 7284234238216418923265911879098470861191745960804303625137027373553619840122494`

Next we should calculate the modular multiplicative inverse of `e(mod λ(n))` to get `d`. Another useful online tool helps here, use [https://www.dcode.fr/modular-inverse](https://www.dcode.fr/modular-inverse).

```python
d = 1/(65537 * mod(7284234238216418923265911879098470861191745960804303625137027373553619840122494)) = 3822119520023592992252745436904927231558688376033971543726629191475988816426329
```

So now we have 

```python
n = 14568468476432837846531823758196941722524462577948878352231306047102565364099933
e = 65537
c = 7686966029791874563175059394981000840074736771341506547944950743609250244624246
d = 3822119520023592992252745436904927231558688376033971543726629191475988816426329
```

I was stuck here again. After searching the web I came across this [StackOverflow question](https://stackoverflow.com/questions/26681374/rsa-decryption-with-large-keys) that provided the following python one-liner that would decrypt my ciphertext. 

```python
m = hex(pow(c, d, n)).rstrip("L")
# m = hex encoded plaintext

>>> m
'0x7069636f4354467b7573335f6c40726733725f7072316d33245f313539397d'
```

I again went to [cyberchef](https://gchq.github.io/CyberChef/), entered the value of `m` in the input pane. I chose the "from hex" operation with a delimiter of `0x` and was given the flag in the output pane:

`picoCTF{us3_l@rg3r_pr1m3$_1599}`

## Supersafe RSA 2

<!--d and e are inverse; what vulns are present when d is small? Wiener Attack.-->
We are given n, e, and c.

```python
c = 33538497995588604996408152117996972621953696640861613118134969889521796779470201586945282006752313209689461633070764531554007793003259003113696492091456566880088643881435941452375339597035502224849198049869554524694812191167571253644179892127798064426824785323248346564905387800002957866428340488446476979594
n = 63120131701742542631724957494679420148151586570934815288349232630271727304242009721612488046773174196932845429956821213827698968828977521387447064786794208725793066207721790578020847445810506678306266767555353160751638816648909663976347413799940711345941628715313434845537627263422696019555484853655016282853
e = 52146318731822428333757791379441046204149890164489123764546630182962328630141372543101834693630162664518288144317746783958269454953802126134558286597668461757547144988283882073767372002785124265125110492425949756547249611589508775885381818549535047174287981914178170971177781513129479762394812965699621809025
```

I don't remember how I figured it out, but I used [Wiener's Attack against RSA](https://en.wikipedia.org/wiki/Wiener%27s_attack) on this one. I searched for and found a wiener.py code online. I entered the values for `e` and `n`, ran it and it returned `p`,`q` and `d`.

```python
p = 7170786058747714673741069762247853387883334331414573762929369366243199754285681902253853367399436099128225124214046581910160575068405605073810198024428357
q = 8802400627298265787773757463511930694530274663935769402705851047894455718800247416582987762784479494875299315150449361526403662752095636522686087505226529
d = 65537
# that's a small private key!
```

I used the python one-liner to get the below output

```python
m = hex(pow(c, d, n)).rstrip("L") 
# m = hex encoded plaintext

>>> m
'0x7069636f4354467b77407463685f793075725f5870306e336e74245f6340723366753131795f353638393635327d'
```

I again went to [cyberchef](https://gchq.github.io/CyberChef/), entered the value of `m` in the input pane. I chose the "from hex" operation with a delimiter of `0x` and was given the flag in the output pane:

`picoCTF{w@tch_y0ur_Xp0n3nt$_c@r3fu11y_5689652}`
