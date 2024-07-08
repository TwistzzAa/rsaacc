package rsaAccumulator

import (
	"awesomeProject/src/utils/pair"
	"awesomeProject/src/utils/util"
	"fmt"
	"math/big"
)

const (
	RSA_KEY_SIZE = 128
	RSA_PRIME_SIZE = RSA_KEY_SIZE/2
	ACCUMULATED_PRIME_SIZE = 128
)

//type RsaInter interface {
//	accumulator.Accumulator
//	GetN() big.Int
//}

type non_mem_witness struct {
	A *big.Int
	B *big.Int
}

type RSAAccumulator struct {
	Data 	map[string]int			//["key":hashPrime]
	Pair 	*pair.Pair
	P		*big.Int
	Q 		*big.Int
	N		*big.Int
	//random 	big.Int
	A0		*big.Int
	A		*big.Int
}

func (rsaObj *RSAAccumulator)GetP() *big.Int {
	return rsaObj.P
}

func (rsaObj *RSAAccumulator)GetQ() *big.Int {
	return rsaObj.Q
}

func (rsaObj *RSAAccumulator)GetN() *big.Int {
	return rsaObj.N
}

func (rsaObj *RSAAccumulator)GetA() *big.Int {
	return rsaObj.A
}

func (rsaObj *RSAAccumulator)GetA0() *big.Int {
	return rsaObj.A0
}

func (rsaObj *RSAAccumulator)GetVal(key string) int {
	return rsaObj.Data[key]
}

//func (rsaObj *RSAAccumulator)AddMember(key *big.Int) *big.Int {
//	_,ok := rsaObj.data[key.String()]
//	if ok{
//		return rsaObj.a
//	}
//	hashPrime,_ :=util.HashToPrime(key)
//	//fmt.Println(hashPrime)
//	rsaObj.a.Exp(rsaObj.a,hashPrime,rsaObj.n)
//	rsaObj.data[key.String()]=hashPrime
//	return rsaObj.a
//}

func (rsaObj *RSAAccumulator)AddMember(key string) *big.Int {
	_,ok := rsaObj.Data[key]
	if ok{
		return rsaObj.A
	}
	hashPrime,count :=util.HashToPrime(key)
	fmt.Println(key,"第一次加入的时候的hash值",hashPrime)
	//fmt.Println(hashPrime)
	rsaObj.A.Exp(rsaObj.A,hashPrime,rsaObj.N)
	//fmt.Println(rsaObj.a.String())
	rsaObj.Data[key]=count
	return rsaObj.A
}

//func (rsaObj *RSAAccumulator)AddMember1(key string) *big.Int {
//	_,ok := rsaObj.data[key]
//	if ok{
//		return rsaObj.a
//	}
//	ketset,_:=new(big.Int).SetString(key,10)
//	hashPrime,count :=util.HashToPrime1(ketset,128,0)
//	fmt.Println("第一次加入的时候的hash值",hashPrime)
//	//fmt.Println(hashPrime)
//	rsaObj.a.Exp(rsaObj.a,hashPrime,rsaObj.n)
//	fmt.Println(rsaObj.a.String())
//	rsaObj.data[key]=count
//	return rsaObj.a
//}

//func (rsaObj *RSAAccumulator)UpdateExistProof(proof string,key string) *big.Int{
//	hashPrime,_ :=util.HashToPrime(key)
//}

func (rsaObj *RSAAccumulator)ProveMembership(key string) *big.Int {
	_,ok := rsaObj.Data[key]
	if !ok{
		return nil
	}
	witness := rsaObj.iterateAndGetProductWithoutX(key)
	return witness.Exp(rsaObj.A0,witness,rsaObj.N)
}

func (rsaObj *RSAAccumulator)DeleteMember(bigInteger big.Int) *big.Int{
	return big.NewInt(0)
}

func (rsaObj *RSAAccumulator)VerifyMembership(key string,proof *big.Int) bool{
	hashPrime,_ := util.HashToPrime(key)
	return	doVerifyMembership(rsaObj.A,hashPrime,proof,rsaObj.N)
}

//func (rsaObj *RSAAccumulator)ProveNonMembership(A big.Int,set []string,x string,g big.Int) *non_mem_witness{
//	primes := big.NewInt(1)
//	for _,element := range set{
//		prime,_ := util.HashToPrime(element)
//		primes.Mul(primes,prime)
//	}
//	x_prime,_ := util.HashToPrime(x)
//	b,a := util.Bezoute_Coefficients(*primes,*x_prime)
//	fmt.Println(&b)
//	fmt.Println(&a)
//	result_b := big.NewInt(1)
//	result_b.Exp(&g,&b,rsaObj.n)
//	non_mem_witness := &non_mem_witness{
//		A: &a,
//		B: result_b,
//	}
//	return non_mem_witness
//}

func (rsaObj *RSAAccumulator)ProveNonmembership(A0 big.Int,set []string,x string,n big.Int) *non_mem_witness{
	for _,val := range set{
		if x==val{
			return nil
		}
	}
	primes := big.NewInt(1)
	for _,element := range set{
		prime,_ := util.HashToPrime(element)
		//fmt.Println("第一次验证的时候的hash值",prime)
		primes.Mul(primes,prime)
	}
	fmt.Println("primes",primes)
	fmt.Println("rsa",rsaObj.A)
	x_prime,_ := util.HashToPrime(x)
	a,b := util.Bezoute_Coefficients(*x_prime,*primes)
	d := big.NewInt(1)
	//inverse_A0 := big.NewInt(1)
	if a.Cmp(big.NewInt(0))<0{
		a.Abs(&a)
		str := n.String()
		computeN,_ := new(big.Int).SetString(str,10)
		str1 := A0.String()
		A01,_ := new(big.Int).SetString(str1,10)
		inverse_A0 := util.Mul_inv(A0,n)
		rsaObj.N = computeN
		rsaObj.A0= A01
		d.Exp(&inverse_A0,&a,computeN)
	}else{
		d.Exp(&A0,&a,&n)
	}
 	//fmt.Println("d",d)
	var result non_mem_witness
	result.A=d
	result.B=&b
	return &result
}

func (rsaObj *RSAAccumulator)ProveNonmembership1(A0 big.Int,set []string,x string,x_noce int,n big.Int) *non_mem_witness{
	for _,val := range set{
		if x==val{
			return nil
		}
	}
	primes := big.NewInt(1)
	for _,element := range set{
		nouce := rsaObj.Data[element]
		element1,_ := new(big.Int).SetString(element,10)
		prime,_ := util.HashToPrime1(element1,128,nouce)
		fmt.Println("第一次验证的时候的hash值",prime)
		primes.Mul(primes,prime)
	}
	xt,_ := new(big.Int).SetString(x,10)
	x_prime,_ := util.HashToPrime1(xt,128,x_noce)
	a,b := util.Bezoute_Coefficients(*x_prime,*primes)
	d := big.NewInt(1)
	//inverse_A0 := big.NewInt(1)
	if a.Cmp(big.NewInt(0))<0{
		a.Abs(&a)
		str := n.String()
		computeN,_ := new(big.Int).SetString(str,10)
		str1 := A0.String()
		A01,_ := new(big.Int).SetString(str1,10)
		inverse_A0 := util.Mul_inv(A0,n)
		rsaObj.N = computeN
		rsaObj.A0= A01
		d.Exp(&inverse_A0,&a,computeN)
	}else{
		d.Exp(&A0,&a,&n)
	}
	fmt.Println("d",d)
	var result non_mem_witness
	result.A=d
	result.B=&b
	return &result
}

func (rsaObj *RSAAccumulator)VerifyNonMembership1(An big.Int,Am big.Int,proof *non_mem_witness,x string,x_nonce int,n big.Int){
	if proof == nil {
		fmt.Println("成员存在")
		return
	}
	xt,_:= new(big.Int).SetString(x,10)
	x_prime,_ := util.HashToPrime1(xt,128,x_nonce)
	//fmt.Println(x_prime)
	//x_prime,_ = new(big.Int).SetString("272223493878286539355298549130271885477",10)
	second_power := big.NewInt(1)
	if proof.B.Cmp(big.NewInt(0))<0{
		proof.B.Abs(proof.B)
		str := n.String()
		computeN,_ := new(big.Int).SetString(str,10)
		str1 := An.String()
		A01,_ := new(big.Int).SetString(str1,10)
		inverse_Am := util.Mul_inv(Am,n)
		rsaObj.N = computeN
		rsaObj.A0= A01
		second_power.Exp(&inverse_Am,proof.B,computeN)
	} else{
		second_power.Exp(&Am,proof.B,&n)
	}
	d := proof.A
	d.Exp(d,x_prime,&n)
	d.Mul(d,second_power)
	d.Mod(d,&n)
	if d.Cmp(&An) == 0 {
		fmt.Println("验证成功")
	} else{
		fmt.Println("验证失败")
	}
}

func (rsaObj *RSAAccumulator)VerifyNonMembership(An big.Int,Am big.Int,proof *non_mem_witness,x string,n big.Int){
	if proof == nil {
		fmt.Println("成员存在")
		return
	}
	x_prime,_ := util.HashToPrime(x)
	//fmt.Println(x_prime)
	//x_prime,_ = new(big.Int).SetString("272223493878286539355298549130271885477",10)
	second_power := big.NewInt(1)
	str := n.String()
	computeN,_ := new(big.Int).SetString(str,10)
	if proof.B.Cmp(big.NewInt(0))<0{
		proof.B.Abs(proof.B)
		str1 := Am.String()
		A01,_ := new(big.Int).SetString(str1,10)
		inverse_Am := util.Mul_inv(Am,n)
		rsaObj.N = computeN
		rsaObj.A= A01
		second_power.Exp(&inverse_Am,proof.B,computeN)
	} else{
		second_power.Exp(&Am,proof.B,&n)
	}
	d := proof.A
	d.Exp(d,x_prime,computeN)
	d.Mul(d,second_power)
	d.Mod(d,computeN)
	if d.Cmp(&An) == 0 {
		fmt.Println("非成员证明验证成功")
	} else{
		fmt.Println("非成员证明验证失败")
	}
}

//func (rsaObj *RSAAccumulator)ProveNoMembership(key *big.Int) *big.Int{
//	v,ok := rsaObj.data[key.String()]
//	if ok{
//		return nil
//	}
//	witness := rsaObj.iterateAndGetProduct()
//
//	return big.NewInt(0)
//}

//func (rsaObj *RSAAccumulator)VerifyNoMembership(){
//
//}

func doVerifyMembership(accumulatorState *big.Int,hashPrime *big.Int,proof *big.Int,n *big.Int) bool{
	result := big.NewInt(1)
	result.Exp(proof,hashPrime,n)
	fmt.Println("当前累加器状态",accumulatorState)
	fmt.Println("当前关键字hash",hashPrime)
	fmt.Println("当前关键字存在性证明",proof)
	fmt.Println("当前result",result)
	if result.Cmp(accumulatorState)==0{
		return true
	}
	return false
}

func (rsaObj *RSAAccumulator)iterateAndGetProductWithoutX(key string) *big.Int{
	result := big.NewInt(1)
	for k,v := range rsaObj.Data{
		if k!=key{
			prime := util.HashToPrimeWithNonce(k,v)
			result.Mul(result,prime)
		}
	}
	return result
}

func (rsaObj *RSAAccumulator)iterateAndGetProduct() *big.Int{
	result := big.NewInt(1)
	for k,v := range rsaObj.Data{
		prime := util.HashToPrimeWithNonce(k,v)
		result.Mul(result,prime)
		result.Mul(result,prime)
	}
	return result
}

func (rsaObj *RSAAccumulator)getPair() *pair.Pair {
	return rsaObj.Pair
}


func New() *RSAAccumulator {
	data := make(map[string]int)
	pair := pair.NewPair(RSA_PRIME_SIZE)
	var N = new(big.Int)
	N.Mul(pair.GetFirst(), pair.GetSecond())
	random := util.GenerateRandomNumber(*big.NewInt(0), *N)
	random2 := big.NewInt(0)
	random2.Set(random)
	return &RSAAccumulator{
		Data: data,
		Pair: pair,
		P:    pair.GetFirst(),
		Q:    pair.GetSecond(),
		N:    N,
		A:    random,
		A0:   random2,
	}
}

//func New1() *RSAAccumulator {
//	data := make(map[string]int)
//	pair := pair.NewPair(RSA_PRIME_SIZE)
//	var N = new(big.Int)
//	N.Mul(pair.GetFirst(), pair.GetSecond())
//	random := util.GenerateRandomNumber(*big.NewInt(0), *N)
//	random2 := big.NewInt(0)
//	random2.Set(random)
//	return &RSAAccumulator{
//		data: data,
//		pair: pair,
//		p:    pair.GetFirst(),
//		q:    pair.GetSecond(),
//		n:    N,
//		a:    random,
//		a0:   random2,
//	}
//}