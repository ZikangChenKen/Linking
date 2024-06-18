package main.rice;
import java.util.*;

/**
 * This class implements a relatively simple algorithm for computing (and printing) the
 * prime factors of a number.  At initialization, a list of primes is computed. Given a
 * number, this list is used to efficiently compute the prime factors of that number.
 */
public class PrimeFactorizer {
    int maxNumToFactorize;
    int[] PrimeList;

    public PrimeFactorizer(int maxNumToFactorize) {
        // TODO: implement this constructor
        this.maxNumToFactorize = maxNumToFactorize;
        this.PrimeList = PrimeCandidate((int)Math.sqrt(this.maxNumToFactorize));
    }

    public int[] computePrimeFactorization(int numToFactorize) {
        // TODO: implement this method
        if(numToFactorize > maxNumToFactorize){
            return null;
        }
        //if (isPrime(numToFactorize)) {
        //    return new int[]{maxNumToFactorize};
        //}
        int [] Factor = PrimeFactor(numToFactorize, this.PrimeList);
        return RecordFactor(numToFactorize, Factor);
    }
    private boolean isPrime(int num){
        if (num < 2){
            return false;
        }
        if (num == 2){
            return true;
        }
        for(int i = 2; i <= Math.sqrt(num); i++){
            if (num % i == 0){
                return false;
            }
        }
        return true;
    }
    private int [] PrimeCandidate(int num){

        if (num <= 1){
            return null;
        }
        if (num == 2){
            return new int []{2};
        }
        int [] temp_candidate = new int[num];
        int count = 0;
        for(int i = 2; i <= num; i++){
            if(isPrime(i)){
                temp_candidate[count] = i;
                count++;
            }
        }
        int [] candidate = new int[count];
        for(int i = 0; i < count; i++)
        {
            candidate[i] = temp_candidate[i];
        }
        return candidate;
    }
    private int[] PrimeFactor(int num, int[] candidate){
        if(num <= 1 || candidate == null){
            return null;
        }
        if(isPrime(num)){
            return new int[]{num};
        }
        int [] temp_factors = new int[num];
        int count = 0;
        for(int i = 0; i < candidate.length; i++){
            if(candidate[i] > num){
                break;
            }
            if(num % candidate[i] == 0){
                temp_factors[count] = candidate[i];
                count++;
            }
        }

        int [] factors = new int[count];
        for(int i = 0; i < count; i++) {
            factors[i] = temp_factors[i];
        }
        return factors;
    }
    private int[] RecordFactor(int num, int[] factors){
        if(num <= 1 || factors == null){
            return null;
        }
        int count = 0;
        int [] temp_result = new int[num];
        int current = num;
        int idx = 0;
        while(current != 1 && idx < factors.length){
            if (isPrime(current)) {
                temp_result[count] = current;
                count++;
                break;
            }
            if(current % factors[idx] == 0){
                temp_result[count] = factors[idx];
                count++;
                current /= factors[idx];
            }
            else{
                idx++;
            }
        }
        int[] result = new int[count];
        for(int i = 0; i < count; i++){
            result[i] = temp_result[i];
        }
        return result;
    }
}