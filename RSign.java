import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;
import java.util.Random;
import java.lang.String;

class RSign{

    public static class Constants {

        // for curve p192
        public static String Curve = "p192";
        public static BigInteger n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");
        public static BigInteger xG = new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16);
        public static BigInteger yG = new BigInteger("07192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16);
        public static BigInteger[] xyG = {xG,yG};
        public static BigInteger a = BigInteger.valueOf(-3); //variable a of the EC equation
    }

public static class EcOperations {

    public static BigInteger[] negation(BigInteger[] p) {
        BigInteger[] q = new BigInteger[2];
        q[0] = p[0];	//same x-coordinate
        q[1] = p[1].multiply(BigInteger.valueOf(-1)); //negating y- coordinate
        return q;
    }

    public static BigInteger[] pointAddition(BigInteger[] p1, BigInteger[] p2, BigInteger n) {
        BigInteger[] val = new BigInteger[2];

        BigInteger a = (p2[1].subtract(p1[1]));
        BigInteger b = (p2[0].subtract(p1[0]));
        b = b.modInverse(n);
        a = a.multiply(b).mod(n);
        b = a.multiply(a);
        b = ((b.subtract(p1[0])).subtract(p2[0])).mod(n);
        val[0] = b;

        val[1] = (a.multiply(p1[0].subtract(b))).subtract(p1[1]).mod(n);

        return val;
    }

    public static BigInteger[] pointDoubling(BigInteger[] p1, BigInteger n, BigInteger a) {
        BigInteger[] val = new BigInteger[2];

        BigInteger i = p1[0].multiply(p1[0]).multiply(BigInteger.valueOf(3)).add(a);
        BigInteger j = (p1[1].multiply(BigInteger.valueOf(2))).modInverse(n);
        i = (i.multiply(j)).mod(n);
        j = i.multiply(i);
        j = (j.subtract(p1[0].multiply(BigInteger.valueOf(2)))).mod(n);
        val[0] = j;

        val[1] = (i.multiply(p1[0].subtract(j))).subtract(p1[1]).mod(n);

        return val;
    }

    public static BigInteger[] pointMultiply(BigInteger[] p1, BigInteger n, BigInteger a, BigInteger mult) {
        BigInteger[] val = new BigInteger[2];
        BigInteger[] doubledP = p1;

        boolean set = false;
        String binMult = mult.toString(2);
        int binMultLen = binMult.length();


        for (int c=binMultLen-1; c>= 0; c--) {
            if (binMult.charAt(c) == '1') {
                if (set) {
                    val = pointAddition(val, doubledP, n);
                } else {
                    val = doubledP;
                    set = true;
                }
            }
            doubledP = pointDoubling(doubledP, n, a);
        }
        return val;
    }

    public static String printPoint(BigInteger[] p) {
        return "("+ p[0].toString() +","+p[1].toString()+")";
    }
}

public static class KeyPair {
    public BigInteger privateKey;
    public BigInteger[] publicKey;


    public KeyPair(BigInteger[] point, BigInteger n, BigInteger a) {
        privateKey = BigIntUtils.randomNumberLessThan(n);
        publicKey = EcOperations.pointMultiply(point, n, a, privateKey);
    }

    public BigInteger[] getPublicKey() {
        return this.publicKey;
    }

    public BigInteger getPrivateKey() {
        return this.privateKey;
    }
}

public static class BigIntUtils {

    public static BigInteger randomNumberLessThan (BigInteger upperLimit){
        BigInteger r;
        Random rnd = new Random();
        do {
            r = new BigInteger(upperLimit.bitLength(), rnd);
        } while (r.compareTo(upperLimit) >= 0);
        return r;
    }
}

public static class Signature{
    public static BigInteger pimage;
    public static BigInteger[] c;
    public static BigInteger[] r;

    Signature (BigInteger pimage, BigInteger[] c, BigInteger[] r)
    {
        this.pimage = pimage;
        this.c = c;
        this.r = r;
    }

    public static Signature messageSign(String message, BigInteger[][] publicKeyList, int index, BigInteger privateKey, BigInteger n, BigInteger a) throws NoSuchAlgorithmException, NumberFormatException  {
        BigInteger pImage = privateKey.multiply(new BigInteger(SHAsum((new BigInteger(publicKeyList[index][0].toString(16) + (publicKeyList[index][1].toString(16)), 16).toByteArray())), 16));
        BigInteger[] c = new BigInteger[publicKeyList.length];
        BigInteger[] r = new BigInteger[publicKeyList.length];
        for(int i = 0; i < publicKeyList.length; i++)
        {
            if(i!=index)
            {
                c[i] = BigIntUtils.randomNumberLessThan(Constants.n); 
                r[i] = BigIntUtils.randomNumberLessThan(Constants.n);
            }
        }
        BigInteger k = BigIntUtils.randomNumberLessThan(Constants.n);
        BigInteger[][] X = new BigInteger[publicKeyList.length][2];
        BigInteger[] Y = new BigInteger[publicKeyList.length];
        for(int i = 0; i < publicKeyList.length; i++)
        {
            if(i!=index)
            {
                X[i] = EcOperations.pointMultiply(publicKeyList[i], Constants.n, Constants.a, c[i]);
                X[i] = EcOperations.pointAddition(X[i], EcOperations.pointMultiply(Constants.xyG, Constants.n, Constants.a, r[i]), Constants.n);
                Y[i] = pImage.multiply(c[i]);
                Y[i] = Y[i].add(r[i].multiply(new BigInteger(SHAsum(new BigInteger(publicKeyList[i][0].toString(16) + (publicKeyList[i][1].toString(16)), 16).toByteArray()), 16)));
                Y[i] = Y[i].mod(Constants.n);
            }
        }
        X[index] = EcOperations.pointMultiply(Constants.xyG, Constants.n, Constants.a, k);
        Y[index] = k.multiply(new BigInteger(SHAsum(new BigInteger(publicKeyList[index][0].toString(16) + (publicKeyList[index][1].toString(16)), 16).toByteArray()), 16));
        Y[index] = Y[index].mod(Constants.n);
        c[index] = new BigInteger(SHAsum(new BigInteger(message, 16).toByteArray()), 16);
        for(int i = 0; i < publicKeyList.length; i++)
        {
            c[index] = new BigInteger(c[index].toString(16)+(X[i][0].toString(16) + (X[i][1].toString(16))), 16);
            c[index] = new BigInteger(c[index].toString(16)+(Y[i]).toString(16), 16);
        }
        c[index] = new BigInteger(SHAsum(c[index].toByteArray()), 16);
        BigInteger Sum = new BigInteger("0", 16);
        for(int i = 0; i < publicKeyList.length; i++)
        {
            if(i!=index){
                Sum = Sum.add(c[i]);
                Sum = Sum.mod(Constants.n);
            }
        }
        c[index] = c[index].subtract(Sum);
        r[index] = k.subtract(privateKey.multiply(c[index]));
        r[index] = r[index].mod(Constants.n);
        Signature signature = new Signature(pImage, c, r);
        return signature;
    }

    public static boolean signatureVer(String message, BigInteger[][] publicKeyList, Signature signature) throws NoSuchAlgorithmException
    {
        System.out.println();
        BigInteger[][] X = new BigInteger[publicKeyList.length][2];
        BigInteger[] Y = new BigInteger[publicKeyList.length];
        for(int i = 0; i < publicKeyList.length; i++)
        {
            X[i] = EcOperations.pointMultiply(publicKeyList[i], Constants.n, Constants.a, signature.c[i]);
            X[i] = EcOperations.pointAddition(X[i], EcOperations.pointMultiply(Constants.xyG, Constants.n, Constants.a, signature.r[i]), Constants.n);
            Y[i] = signature.pimage.multiply(signature.c[i]);
            Y[i] = Y[i].mod(Constants.n);
            Y[i] = Y[i].add(signature.r[i].multiply(new BigInteger(SHAsum(new BigInteger(publicKeyList[i][0].toString(16) + (publicKeyList[i][1]).toString(16), 16).toByteArray()), 16)));
            Y[i] = Y[i].mod(Constants.n);
        }
        BigInteger Sum = new BigInteger("0", 16);
        for(int i = 0; i < publicKeyList.length; i++)
        {
            Sum = Sum.add(c[i]);
        }
        Sum = Sum.mod(Constants.n);
        BigInteger result = new BigInteger(SHAsum(new BigInteger(message, 16).toByteArray()), 16);
        for(int i = 0; i < publicKeyList.length; i++)
        {
            result = new BigInteger(result.toString(16)+(X[i][0].toString(16)+(X[i][1]).toString(16)), 16);
            result = new BigInteger(result.toString(16)+(Y[i]).toString(16), 16);
        }
        result = new BigInteger(SHAsum(result.toByteArray()), 16);
        result = result.mod(Constants.n);
        if(Sum.mod(Constants.n).equals(Sum))
            return true;
        else
            return false;
    }

    public static String SHAsum(byte[] convertme) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return byteArray2Hex(md.digest(convertme));
    }


    private static String byteArray2Hex(byte[] hash) {
        Formatter formatter = new Formatter();
        try{
            for (byte b : hash) {
                formatter.format("%02x", b);
            }
            return formatter.toString();
        }finally {
            formatter.close();
        }

    }
}

    public static void main(String[] args) throws NoSuchAlgorithmException, NumberFormatException {
        BigInteger big = new BigInteger("12473953");
        String msg = String.format("%02x", big);
        KeyPair[] kps = new KeyPair[10];
        for(int i = 0; i < 10; i++) 
            kps[i] = new KeyPair(Constants.xyG, Constants.n, Constants.a);
        BigInteger[][] publicKeyList = new BigInteger[10][2];
        for(int i = 0; i < 10; i++)                                                       
        {
            publicKeyList[i][0] = kps[i].publicKey[0];
            publicKeyList[i][1] = kps[i].publicKey[1];
        }
        BigInteger[] privateKeyList = new BigInteger[10];
        for(int i = 0; i < 10; i++)
        {
            privateKeyList[i] = kps[i].privateKey;
        }
        Signature signature = Signature.messageSign(msg, publicKeyList, 9, privateKeyList[9], Constants.n, Constants.a);

        boolean verified = Signature.signatureVer(msg, publicKeyList, signature);
        System.out.println("Signature Verification Status :: "+verified);
    }
}
