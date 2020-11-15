package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
)

func main() {

	// 암호 생성을 위한 타원 곡선 생성
	curve := elliptic.P256()

	// 송신자 타원곡선 암호 키 쌍(비밀키, 공개키) 생성

	privateKey1, _ := ecdsa.GenerateKey(curve, rand.Reader)
	publicKey1 := append(privateKey1.PublicKey.X.Bytes(), privateKey1.PublicKey.Y.Bytes()...)

	// 키 쌍
	// fmt.Println()
	// fmt.Println("private key 1 => ", privateKey1)
	// fmt.Println()
	// fmt.Println("public key 1 => ", publicKey1)
	// fmt.Println()

	//	fmt.Sprintf("%s", privateKey1)
	//	fmt.Sprintf("%s", publicKey1)

	// 송신자 주소 생성

	pubKeyHash1 := HashPubKey(publicKey1)

	versionedPayload1 := append([]byte{version}, pubKeyHash1...)
	checksum1 := checksum(versionedPayload1)

	fullPayload1 := append(versionedPayload1, checksum1...)
	address1 := Base58Encode(fullPayload1)

	// 송신자 주소 출력
	address1Valid := fmt.Sprintf("%s", address1)
	// fmt.Println("송신자 주소 출력 ")
	// fmt.Println("address1 => ", address1)
	// fmt.Println()

	// 송신자 원문 메시지
	messageBuf1 := []byte("안녕하세요. 모두들!")
	fmt.Println("송신자 원문 메시지")
	fmt.Println("=> ", string(messageBuf1))
	fmt.Println("=> ", messageBuf1)
	fmt.Println()

	// 송신자 메시지에 대한 SHA256 해쉬값
	messageHashedBuf1 := sha256.Sum256(messageBuf1)
	// fmt.Println("송신자 메시지에 대한 SHA256 해쉬값 생성 ...... ")
	// fmt.Println("messageHashedBuf1 => ", messageHashedBuf1)
	// fmt.Println()

	// 비밀키를 이용해서 송신자 메시지에 대한 전자서명 생성
	r1, s1, _ := ecdsa.Sign(rand.Reader, privateKey1, messageHashedBuf1[:])
	messageHashedBuf1Signature1 := append(r1.Bytes(), s1.Bytes()...)
	// fmt.Println("비밀키를 이용해서 송신자 메시지에 대한 전자서명 생성 ...... ")
	// fmt.Println("messageHashedBuf1Signature1 => ", messageHashedBuf1Signature1)
	// fmt.Println()

	/*

		송신자 측

	*/

	fmt.Println("메시지 송신 중................ ")
	fmt.Println()

	///////////////////////////////////////////////////////////////
	//                                                           //
	//         전송 네트워크 경계 (송신자, 수신자 경계)           //
	fmt.Println()
	fmt.Println("메시지 네트워크 전송 중................ ")
	fmt.Println()
	fmt.Println()
	//                                                           //
	///////////////////////////////////////////////////////////////

	fmt.Println()
	fmt.Println("메시지 수신 중................ ")
	fmt.Println()
	fmt.Println()

	// 송신자측 주소 유효성 확인
	if !ValidateAddress(address1Valid /* from */) {
		log.Panic("ERROR: Sender address is not valid")
	} else {
		fmt.Println("송신자의 유효한 주소 확인................ ")
		fmt.Println()
		fmt.Println()
	}

	/*

		수신자 측

	*/

	// 수신된 메시지 버퍼들 생성 중
	// 수신자 네트워크로 전송된 버퍼 값들을 묘사한다.
	messageBuf2 := messageBuf1
	messageHashedBuf2 := messageHashedBuf1
	messageHashedBuf1Signature2 := messageHashedBuf1Signature1
	publicKey2 := publicKey1

	r2 := big.Int{}
	s2 := big.Int{}
	sigLen := len(messageHashedBuf1Signature2)
	// fmt.Println("sigLen => ", sigLen)
	// fmt.Println("messageHashedBuf1Signature2 => ", messageHashedBuf1Signature2)

	r2.SetBytes(messageHashedBuf1Signature2[:(sigLen / 2)])
	s2.SetBytes(messageHashedBuf1Signature2[(sigLen / 2):])

	x := big.Int{}
	y := big.Int{}
	keyLen := len(publicKey2)
	//fmt.Println("keyLen => ", keyLen)
	//fmt.Println("publicKey2 => ", publicKey2)

	x.SetBytes(publicKey2[:(keyLen / 2)])
	y.SetBytes(publicKey2[(keyLen / 2):])

	// 수신된 공개키 바이트 스트림을 cryto/ecdsa.PublicKey 형태로 복원
	rawPubKey := ecdsa.PublicKey{curve, &x, &y}

	// fmt.Println()
	// fmt.Println("rawPubKey => ", rawPubKey)
	// fmt.Println()

	// 수신된 전자서명 확인
	if ecdsa.Verify(&rawPubKey, messageHashedBuf2[:], &r2, &s2) == false {

		fmt.Println("전자서명 검증 실패 !!! ")
		fmt.Println()
		fmt.Println("송신자 원본 메시지는 훼손 혹은 위변조 의심됨 !!! ")
		fmt.Println("=> ", messageBuf2)
		fmt.Println("=> ", string(messageBuf2))
		fmt.Println()

	} else {

		fmt.Println("전자서명 검증 성공 !!! ")
		fmt.Println()
		fmt.Println("송신자 원본 메시지는 원본 임이 검증됨 !!! ")
		fmt.Println("=> ", messageBuf2)
		fmt.Println("=> ", string(messageBuf2))
		fmt.Println()

	}

}
