import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

public class TxHandler {

    private UTXOPool utxoPool;
    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        HashSet<UTXO> utxoSet = new HashSet<>();
        double inSum = 0;
        for (int i = 0; i < tx.getInputs().size(); i++) {
            Transaction.Input in = tx.getInput(i);
            UTXO utxoOfInput = new UTXO(in.prevTxHash, in.outputIndex);
            // 3. no UTXO is claimed multiple times by tx
            if (utxoSet.contains(utxoOfInput)) return false;
            utxoSet.add(utxoOfInput);
            // 1. all outputs claimed by tx are in the current UTXO pool
            if (!utxoPool.contains(utxoOfInput)) return false;
            Transaction.Output prevOut = utxoPool.getTxOutput(utxoOfInput);
            PublicKey inputPK = prevOut.address;
            // 2. the signatures on each input of tx are valid
            boolean verified = Crypto.verifySignature(inputPK, tx.getRawDataToSign(i), in.signature);
            if (!verified) return false;
            inSum += prevOut.value;
        }
        double outSum = 0;
        for (Transaction.Output out : tx.getOutputs()) {
            // 4. all of tx's output value are non-negative
            if (out.value < 0) return false;
            outSum += out.value;
        }
        // 5. the sum of tx's input values is greater than or equal to the sum of its output values
        return inSum >= outSum;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        List<Transaction> res = new ArrayList<>();
        for (Transaction tx : possibleTxs) {
            if (isValidTx(tx)) {
                res.add(handleTx(tx));
            }
        }
        return res.toArray(new Transaction[0]);
    }
    // check validation before calling this function
    private Transaction handleTx(Transaction tx) {
        // remove used UTXO
        for (Transaction.Input in : tx.getInputs()) {
            UTXO spent = new UTXO(in.prevTxHash, in.outputIndex);
            utxoPool.removeUTXO(spent);
        }
        // add new UTXO
        for (int i = 0; i < tx.getOutputs().size(); i++) {
            UTXO utxo = new UTXO(tx.getHash(), i);
            Transaction.Output out = tx.getOutput(i);
            utxoPool.addUTXO(utxo, out);
        }
        return tx;
    }

}
